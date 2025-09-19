use std::str::FromStr;

use indexmap::IndexMap;
use one_crypto::utilities;
use one_dto_mapper::convert_inner;
use secrecy::SecretString;
use shared_types::{CredentialId, CredentialSchemaId};
use time::OffsetDateTime;
use tokio_util::either::Either;
use uuid::Uuid;

use super::OID4VCIFinal1_0Service;
use super::dto::{OpenID4VCICredentialResponseDTO, OpenID4VCICredentialResponseEntryDTO};
use super::mapper::interaction_data_to_dto;
use super::nonce::{generate_nonce, validate_nonce};
use super::validator::{
    throw_if_access_token_invalid, throw_if_credential_request_invalid,
    validate_config_entity_presence,
};
use crate::common_mapper::{
    IdentifierRole, get_exchange_param_pre_authorization_expires_in,
    get_exchange_param_refresh_token_expires_in, get_exchange_param_token_expires_in,
    get_or_create_did_and_identifier, get_or_create_key_identifier,
};
use crate::common_validator::throw_if_credential_state_not_eq;
use crate::config::ConfigValidationError;
use crate::config::core_config::IssuanceProtocolType;
use crate::model::certificate::CertificateRelations;
use crate::model::claim::{Claim, ClaimRelations};
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential::{CredentialRelations, CredentialStateEnum, UpdateCredentialRequest};
use crate::model::credential_schema::{
    CredentialSchemaRelations, CredentialSchemaType, WalletStorageTypeEnum,
};
use crate::model::did::{DidRelations, KeyRole};
use crate::model::identifier::IdentifierRelations;
use crate::model::interaction::{InteractionRelations, UpdateInteractionRequest};
use crate::model::organisation::OrganisationRelations;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::issuance_protocol::error::{
    IssuanceProtocolError, OpenID4VCIError, OpenIDIssuanceError,
};
use crate::provider::issuance_protocol::openid4vci_final1_0::mapper::map_proof_types_supported;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::{
    ExtendedSubjectClaimsDTO, ExtendedSubjectDTO, OpenID4VCICredentialOfferDTO,
    OpenID4VCICredentialRequestDTO, OpenID4VCICredentialRequestProofs,
    OpenID4VCICredentialValueDetails, OpenID4VCIDiscoveryResponseDTO, OpenID4VCIFinal1Params,
    OpenID4VCIIssuerInteractionDataDTO, OpenID4VCIIssuerMetadataResponseDTO,
    OpenID4VCINonceResponseDTO, OpenID4VCINotificationEvent, OpenID4VCINotificationRequestDTO,
    OpenID4VCITokenRequestDTO, OpenID4VCITokenResponseDTO, Timestamp,
};
use crate::provider::issuance_protocol::openid4vci_final1_0::proof_formatter::OpenID4VCIProofJWTFormatter;
use crate::provider::issuance_protocol::openid4vci_final1_0::service::{
    create_credential_offer, create_issuer_metadata_response, create_service_discovery_response,
    get_credential_schema_base_url, oidc_issuer_create_token, parse_access_token,
    parse_refresh_token,
};
use crate::provider::revocation::model::{CredentialRevocationState, Operation};
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError,
};
use crate::service::ssi_validator::validate_issuance_protocol_type;
use crate::util::key_verification::KeyVerification;
use crate::util::oidc::map_to_openid4vp_format;
use crate::util::revocation_update::{generate_credential_additional_data, process_update};

impl OID4VCIFinal1_0Service {
    pub async fn get_issuer_metadata(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<OpenID4VCIIssuerMetadataResponseDTO, ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let protocol_base_url =
            self.protocol_base_url
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "Host URL not specified".to_string(),
                ))?;

        let schema = self
            .credential_schema_repository
            .get_credential_schema(
                credential_schema_id,
                &CredentialSchemaRelations {
                    claim_schemas: Some(ClaimSchemaRelations::default()),
                    organisation: Some(OrganisationRelations::default()),
                },
            )
            .await?;

        let Some(schema) = schema else {
            return Err(EntityNotFoundError::CredentialSchema(*credential_schema_id).into());
        };

        let format_type = self
            .config
            .format
            .get_fields(&schema.format)
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?
            .r#type;
        let oidc_format = map_to_openid4vp_format(&format_type).map(|s| s.to_string())?;

        let formatter = self
            .formatter_provider
            .get_credential_formatter(&schema.format)
            .ok_or(MissingProviderError::Formatter(schema.format.to_owned()))?;

        let credential_signing_alg_values_supported = formatter
            .get_capabilities()
            .signing_key_algorithms
            .into_iter()
            .filter_map(|alg_type| {
                self.key_algorithm_provider
                    .key_algorithm_from_type(alg_type)
                    .and_then(|alg| alg.issuance_jose_alg_id())
            })
            .collect();

        create_issuer_metadata_response(
            protocol_base_url,
            &oidc_format,
            &schema,
            &self.config,
            &self.did_method_provider.supported_method_names(),
            Some(map_proof_types_supported(
                self.key_algorithm_provider
                    .supported_verification_jose_alg_ids(),
            )),
            credential_signing_alg_values_supported,
        )
        .map_err(Into::into)
    }

    pub async fn service_discovery(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<OpenID4VCIDiscoveryResponseDTO, ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let protocol_base_url =
            self.protocol_base_url
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "Host URL not specified".to_string(),
                ))?;

        let schema = self
            .credential_schema_repository
            .get_credential_schema(
                credential_schema_id,
                &CredentialSchemaRelations {
                    claim_schemas: Some(ClaimSchemaRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        let Some(schema) = schema else {
            return Err(EntityNotFoundError::CredentialSchema(*credential_schema_id).into());
        };

        let schema_base_url = get_credential_schema_base_url(&schema.id, protocol_base_url);
        Ok(create_service_discovery_response(&schema_base_url)?)
    }

    pub async fn get_credential_offer(
        &self,
        credential_schema_id: CredentialSchemaId,
        credential_id: CredentialId,
    ) -> Result<OpenID4VCICredentialOfferDTO, ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let credential = self
            .credential_repository
            .get_credential(
                &credential_id,
                &CredentialRelations {
                    claims: Some(ClaimRelations {
                        schema: Some(ClaimSchemaRelations::default()),
                    }),
                    issuer_identifier: Some(IdentifierRelations {
                        did: Some(Default::default()),
                        ..Default::default()
                    }),
                    schema: Some(CredentialSchemaRelations {
                        claim_schemas: Some(ClaimSchemaRelations::default()),
                        ..Default::default()
                    }),
                    interaction: Some(InteractionRelations::default()),
                    issuer_certificate: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await?;

        let Some(credential) = credential else {
            return Err(EntityNotFoundError::Credential(credential_id).into());
        };

        throw_if_credential_state_not_eq(&credential, CredentialStateEnum::Pending)
            .map_err(|_| ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidRequest))?;

        let issuance_protocol_type = self
            .config
            .issuance_protocol
            .get_fields(&credential.protocol)?
            .r#type;

        if issuance_protocol_type != IssuanceProtocolType::OpenId4VciFinal1_0 {
            return Err(OpenID4VCIError::InvalidRequest.into());
        }
        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "credential schema missing".to_string(),
            ))?;

        if credential_schema.id != credential_schema_id {
            return Err(OpenID4VCIError::InvalidRequest.into());
        }

        let interaction = credential
            .interaction
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "interaction missing".to_string(),
            ))?;

        let url = self
            .protocol_base_url
            .as_ref()
            .ok_or(ServiceError::Other("Missing base_url".to_owned()))?;

        let wallet_storage_type = credential
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError("schema missing".to_string()))?
            .wallet_storage_type;

        let claims = credential
            .claims
            .as_ref()
            .ok_or(ServiceError::MappingError("claims missing".to_string()))?
            .iter()
            .map(|claim| claim.to_owned())
            .collect::<Vec<_>>();

        let params: OpenID4VCIFinal1Params =
            self.config.issuance_protocol.get(&credential.protocol)?;

        let credential_subject = credentials_format(
            wallet_storage_type,
            &claims,
            params.enable_credential_preview,
        )
        .map_err(|e| ServiceError::MappingError(e.to_string()))?;

        Ok(create_credential_offer(
            url,
            &interaction.id.to_string(),
            &credential,
            &credential_schema_id,
            &credential_schema.schema_id,
            credential_subject,
        )?)
    }

    pub async fn create_credential(
        &self,
        credential_schema_id: &CredentialSchemaId,
        access_token: &str,
        request: OpenID4VCICredentialRequestDTO,
    ) -> Result<OpenID4VCICredentialResponseDTO, ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let Some(schema) = self
            .credential_schema_repository
            .get_credential_schema(
                credential_schema_id,
                &CredentialSchemaRelations {
                    organisation: Some(OrganisationRelations::default()),
                    ..Default::default()
                },
            )
            .await?
        else {
            return Err(EntityNotFoundError::CredentialSchema(*credential_schema_id).into());
        };

        throw_if_credential_request_invalid(&schema, &request)?;

        let interaction_id = parse_access_token(access_token)?;
        let Some(interaction) = self
            .interaction_repository
            .get_interaction(
                &interaction_id,
                &InteractionRelations {
                    organisation: Some(Default::default()),
                },
            )
            .await?
        else {
            return Err(
                BusinessLogicError::MissingInteractionForAccessToken { interaction_id }.into(),
            );
        };

        let mut interaction_data = interaction_data_to_dto(&interaction)?;
        throw_if_access_token_invalid(&interaction_data, access_token)?;

        let credentials = self
            .credential_repository
            .get_credentials_by_interaction_id(
                &interaction.id,
                &CredentialRelations {
                    interaction: Some(InteractionRelations::default()),
                    schema: Some(CredentialSchemaRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        let Some(credential) = credentials.iter().find(|credential| {
            credential
                .schema
                .as_ref()
                .is_some_and(|schema| schema.id == *credential_schema_id)
        }) else {
            return Err(
                BusinessLogicError::MissingCredentialsForInteraction { interaction_id }.into(),
            );
        };

        validate_issuance_protocol_type(
            IssuanceProtocolType::OpenId4VciFinal1_0,
            &self.config,
            &credential.protocol,
        )?;

        let Some(OpenID4VCICredentialRequestProofs::Jwt(jwts)) = request.proofs.as_ref() else {
            return Err(OpenID4VCIError::InvalidOrMissingProof.into());
        };
        let Some(jwt) = jwts.first() else {
            return Err(OpenID4VCIError::InvalidOrMissingProof.into());
        };

        let (verified_proof, nonce) = OpenID4VCIProofJWTFormatter::verify_proof(
            jwt,
            Box::new(KeyVerification {
                key_algorithm_provider: self.key_algorithm_provider.clone(),
                did_method_provider: self.did_method_provider.clone(),
                key_role: KeyRole::Authentication,
                certificate_validator: self.certificate_validator.clone(),
            }),
        )
        .await
        .map_err(|_| ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidOrMissingProof))?;

        let params: OpenID4VCIFinal1Params =
            self.config.issuance_protocol.get(&credential.protocol)?;
        let Some(params) = params.nonce else {
            return Err(ConfigValidationError::TypeNotFound(credential.protocol.to_owned()).into());
        };
        validate_nonce(
            params,
            self.base_url.to_owned(),
            &nonce.ok_or(FormatterError::CouldNotVerify("Missing nonce".to_string()))?,
        )?;

        let (holder_identifier, holder_key_id) = match verified_proof {
            Either::Left((holder_did_value, holder_key_id)) => {
                let (_, identifier) = get_or_create_did_and_identifier(
                    &*self.did_method_provider,
                    &*self.did_repository,
                    &*self.identifier_repository,
                    &schema.organisation,
                    &holder_did_value,
                    IdentifierRole::Holder,
                )
                .await?;
                (identifier, holder_key_id)
            }
            Either::Right(jwk) => {
                let (key, identifier) = get_or_create_key_identifier(
                    self.key_repository.as_ref(),
                    self.key_algorithm_provider.as_ref(),
                    self.identifier_repository.as_ref(),
                    schema.organisation.as_ref(),
                    &jwk,
                    IdentifierRole::Holder,
                )
                .await?;

                (identifier, key.id.to_string())
            }
        };

        self.credential_repository
            .update_credential(
                credential.id,
                UpdateCredentialRequest {
                    issuance_date: Some(OffsetDateTime::now_utc()),
                    holder_identifier_id: Some(holder_identifier.id),
                    ..Default::default()
                },
            )
            .await?;

        let issued_credential = self
            .protocol_provider
            .get_protocol(&credential.protocol)
            .ok_or(ServiceError::MappingError(
                "issuance protocol not found".to_string(),
            ))?
            .issuer_issue_credential(&credential.id, holder_identifier, holder_key_id)
            .await;

        match issued_credential {
            Ok(issued_credential) => {
                if let Some(notification_id) = &issued_credential.notification_id {
                    interaction_data.notification_id = Some(notification_id.to_owned());

                    let data = serde_json::to_vec(&interaction_data)
                        .map_err(|e| ServiceError::MappingError(e.to_string()))?;

                    self.interaction_repository
                        .update_interaction(UpdateInteractionRequest {
                            id: interaction.id,
                            data: Some(data),
                            host: interaction.host,
                            organisation: interaction.organisation,
                        })
                        .await?;
                }

                Ok(OpenID4VCICredentialResponseDTO {
                    redirect_uri: issued_credential.redirect_uri,
                    credentials: Some(vec![OpenID4VCICredentialResponseEntryDTO {
                        credential: issued_credential.credential,
                    }]),
                    transaction_id: None,
                    interval: None,
                    notification_id: issued_credential.notification_id,
                })
            }
            Err(err @ IssuanceProtocolError::Suspended)
            | Err(err @ IssuanceProtocolError::RefreshTooSoon) => {
                // propagate error to client but do _not_ put credential to Errored state¬
                Err(err.into())
            }
            Err(error) => {
                self.credential_repository
                    .update_credential(
                        credential.id,
                        UpdateCredentialRequest {
                            state: Some(CredentialStateEnum::Error),
                            ..Default::default()
                        },
                    )
                    .await?;
                Err(error.into())
            }
        }
    }

    pub async fn handle_notification(
        &self,
        credential_schema_id: &CredentialSchemaId,
        access_token: &str,
        request: OpenID4VCINotificationRequestDTO,
    ) -> Result<(), ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let interaction_id = parse_access_token(access_token)?;
        let Some(interaction) = self
            .interaction_repository
            .get_interaction(&interaction_id, &InteractionRelations::default())
            .await?
        else {
            return Err(OpenID4VCIError::InvalidNotificationRequest.into());
        };

        let interaction_data = interaction_data_to_dto(&interaction)?;
        throw_if_access_token_invalid(&interaction_data, access_token)?;

        if Some(request.notification_id) != interaction_data.notification_id {
            return Err(OpenID4VCIError::InvalidNotificationId.into());
        }

        let credentials = self
            .credential_repository
            .get_credentials_by_interaction_id(
                &interaction.id,
                &CredentialRelations {
                    issuer_identifier: Some(IdentifierRelations {
                        did: Some(DidRelations {
                            keys: Some(Default::default()),
                            ..Default::default()
                        }),
                        certificates: Some(CertificateRelations {
                            key: Some(Default::default()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    interaction: Some(InteractionRelations::default()),
                    schema: Some(CredentialSchemaRelations::default()),
                    key: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await?;

        let Some(credential) = credentials.iter().find(|credential| {
            credential
                .schema
                .as_ref()
                .is_some_and(|schema| schema.id == *credential_schema_id)
        }) else {
            return Err(OpenID4VCIError::InvalidNotificationRequest.into());
        };

        match (credential.state, &request.event) {
            (
                CredentialStateEnum::Accepted
                | CredentialStateEnum::Suspended
                | CredentialStateEnum::Revoked,
                _,
            ) => {
                // ok, can be processed
            }
            // repeated requests also allowed
            (CredentialStateEnum::Error, OpenID4VCINotificationEvent::CredentialFailure)
            | (CredentialStateEnum::Rejected, OpenID4VCINotificationEvent::CredentialDeleted) => {
                return Ok(());
            }
            // anything else is invalid
            _ => {
                return Err(OpenID4VCIError::InvalidNotificationRequest.into());
            }
        };

        tracing::debug!(
            "Credential notified: {:?}, description: {:?}",
            request.event,
            request.event_description
        );

        let new_state = match request.event {
            OpenID4VCINotificationEvent::CredentialAccepted => {
                // nothing to do
                return Ok(());
            }
            OpenID4VCINotificationEvent::CredentialFailure => CredentialStateEnum::Error,
            OpenID4VCINotificationEvent::CredentialDeleted => CredentialStateEnum::Rejected,
        };

        if credential.state == new_state {
            // nothing to do
            return Ok(());
        }

        let schema = credential
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError("schema is None".to_string()))?;

        let revocation_method = self
            .revocation_method_provider
            .get_revocation_method(&schema.revocation_method)
            .ok_or(MissingProviderError::RevocationMethod(
                schema.revocation_method.to_owned(),
            ))?;

        // mark the credential as revoked (if supported and not done before)
        if matches!(
            credential.state,
            CredentialStateEnum::Accepted | CredentialStateEnum::Suspended
        ) && revocation_method
            .get_capabilities()
            .operations
            .contains(&Operation::Revoke)
        {
            let update = revocation_method
                .mark_credential_as(
                    credential,
                    CredentialRevocationState::Revoked,
                    generate_credential_additional_data(
                        credential,
                        &*self.credential_repository,
                        &*self.revocation_list_repository,
                        &*revocation_method,
                        &*self.formatter_provider,
                        &*self.key_provider,
                        &self.key_algorithm_provider,
                        &self.base_url,
                    )
                    .await?,
                )
                .await?;

            process_update(
                update,
                &*self.validity_credential_repository,
                &*self.revocation_list_repository,
            )
            .await?;
        }

        self.credential_repository
            .update_credential(
                credential.id,
                UpdateCredentialRequest {
                    state: Some(new_state),
                    ..Default::default()
                },
            )
            .await?;

        Ok(())
    }

    pub async fn create_token(
        &self,
        credential_schema_id: &CredentialSchemaId,
        request: OpenID4VCITokenRequestDTO,
    ) -> Result<OpenID4VCITokenResponseDTO, ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let Some(credential_schema) = self
            .credential_schema_repository
            .get_credential_schema(credential_schema_id, &CredentialSchemaRelations::default())
            .await?
        else {
            return Err(EntityNotFoundError::CredentialSchema(*credential_schema_id).into());
        };

        let interaction_id = match &request {
            OpenID4VCITokenRequestDTO::PreAuthorizedCode {
                pre_authorized_code,
                tx_code: _,
            } => Uuid::from_str(pre_authorized_code).map_err(|_| {
                ServiceError::OpenIDIssuanceError(OpenIDIssuanceError::OpenID4VCI(
                    OpenID4VCIError::InvalidRequest,
                ))
            })?,
            OpenID4VCITokenRequestDTO::AuthorizationCode { .. } => {
                return Err(ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidGrant));
            }
            OpenID4VCITokenRequestDTO::RefreshToken { refresh_token } => {
                parse_refresh_token(refresh_token)?
            }
        };

        let credentials = self
            .credential_repository
            .get_credentials_by_interaction_id(
                &interaction_id,
                &CredentialRelations {
                    interaction: Some(InteractionRelations {
                        organisation: Some(OrganisationRelations::default()),
                    }),
                    ..Default::default()
                },
            )
            .await?;

        let credential = credentials
            .first()
            .ok_or(BusinessLogicError::MissingCredentialsForInteraction { interaction_id })?;

        validate_issuance_protocol_type(
            IssuanceProtocolType::OpenId4VciFinal1_0,
            &self.config,
            &credential.protocol,
        )?;

        let mut interaction = credential
            .interaction
            .clone()
            .ok_or(ServiceError::MappingError(
                "interaction is None".to_string(),
            ))?;

        // both refresh and access token have the same structure
        let generate_new_token = || {
            SecretString::from(format!(
                "{}.{}",
                interaction_id,
                utilities::generate_alphanumeric(32)
            ))
        };

        let pre_authorization_expires_in =
            get_exchange_param_pre_authorization_expires_in(&self.config, &credential.protocol)?;
        let access_token_expires_in =
            get_exchange_param_token_expires_in(&self.config, &credential.protocol)?;
        let refresh_token_expires_in =
            get_exchange_param_refresh_token_expires_in(&self.config, &credential.protocol)?;

        let interaction_data = interaction_data_to_dto(&interaction)?;

        let mut response = oidc_issuer_create_token(
            &interaction_data,
            &convert_inner(credentials.to_owned()),
            &interaction,
            &request,
            pre_authorization_expires_in,
            access_token_expires_in,
            refresh_token_expires_in,
        )?;

        let now = OffsetDateTime::now_utc();
        if let OpenID4VCITokenRequestDTO::PreAuthorizedCode { .. } = &request {
            for credential in &credentials {
                self.credential_repository
                    .update_credential(
                        credential.id,
                        UpdateCredentialRequest {
                            state: Some(CredentialStateEnum::Offered),
                            ..Default::default()
                        },
                    )
                    .await?;
            }

            // we add refresh token for mdoc
            if credential_schema.schema_type == CredentialSchemaType::Mdoc {
                response.refresh_token = Some(generate_new_token());
                response.refresh_token_expires_in =
                    Some(Timestamp((now + refresh_token_expires_in).unix_timestamp()));
            }
        }

        let interaction_data: OpenID4VCIIssuerInteractionDataDTO = (&response).try_into()?;
        let data = serde_json::to_vec(&interaction_data)
            .map_err(|e| ServiceError::MappingError(e.to_string()))?;
        interaction.data = Some(data);

        self.interaction_repository
            .update_interaction(interaction.into())
            .await?;

        Ok(response)
    }

    pub async fn generate_nonce(
        &self,
        protocol_id: &str,
    ) -> Result<OpenID4VCINonceResponseDTO, ServiceError> {
        validate_issuance_protocol_type(
            IssuanceProtocolType::OpenId4VciFinal1_0,
            &self.config,
            protocol_id,
        )?;

        let params: OpenID4VCIFinal1Params = self.config.issuance_protocol.get(protocol_id)?;
        let Some(params) = params.nonce else {
            return Err(ConfigValidationError::TypeNotFound(protocol_id.to_string()).into());
        };

        let c_nonce = generate_nonce(params, self.base_url.to_owned()).await?;
        Ok(OpenID4VCINonceResponseDTO { c_nonce })
    }
}

pub(crate) fn credentials_format(
    wallet_storage_type: Option<WalletStorageTypeEnum>,
    claims: &[Claim],
    claims_with_values: bool,
) -> Result<ExtendedSubjectDTO, OpenIDIssuanceError> {
    Ok(ExtendedSubjectDTO {
        wallet_storage_type,
        keys: Some(ExtendedSubjectClaimsDTO {
            claims: IndexMap::from_iter(
                claims
                    .iter()
                    .filter(|claim| claim.value.is_some())
                    .filter_map(|claim| {
                        claim.schema.as_ref().map(|schema| {
                            (
                                claim.path.clone(),
                                OpenID4VCICredentialValueDetails {
                                    value: match claims_with_values {
                                        true => claim.value.clone(),
                                        false => None,
                                    },
                                    value_type: schema.data_type.clone(),
                                },
                            )
                        })
                    }),
            ),
        }),
    })
}

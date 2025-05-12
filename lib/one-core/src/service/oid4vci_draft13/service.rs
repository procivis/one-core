use std::str::FromStr;

use indexmap::IndexMap;
use one_crypto::utilities;
use one_dto_mapper::convert_inner;
use secrecy::SecretString;
use shared_types::{CredentialId, CredentialSchemaId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::OID4VCIDraft13Service;
use super::dto::OpenID4VCICredentialResponseDTO;
use crate::common_mapper::{
    DidRole, get_exchange_param_pre_authorization_expires_in,
    get_exchange_param_refresh_token_expires_in, get_exchange_param_token_expires_in,
    get_or_create_did_and_identifier,
};
use crate::common_validator::throw_if_credential_state_not_eq;
use crate::config::core_config::IssuanceProtocolType;
use crate::model::claim::{Claim, ClaimRelations};
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential::{CredentialRelations, CredentialStateEnum, UpdateCredentialRequest};
use crate::model::credential_schema::{CredentialSchemaRelations, WalletStorageTypeEnum};
use crate::model::did::KeyRole;
use crate::model::identifier::IdentifierRelations;
use crate::model::interaction::InteractionRelations;
use crate::model::organisation::OrganisationRelations;
use crate::provider::issuance_protocol::error::IssuanceProtocolError;
use crate::provider::issuance_protocol::openid4vci_draft13::error::{
    OpenID4VCIError, OpenIDIssuanceError,
};
use crate::provider::issuance_protocol::openid4vci_draft13::mapper::map_proof_types_supported;
use crate::provider::issuance_protocol::openid4vci_draft13::model::{
    ExtendedSubjectClaimsDTO, ExtendedSubjectDTO, OpenID4VCICredentialOfferDTO,
    OpenID4VCICredentialRequestDTO, OpenID4VCICredentialValueDetails,
    OpenID4VCIDiscoveryResponseDTO, OpenID4VCIIssuerInteractionDataDTO,
    OpenID4VCIIssuerMetadataResponseDTO, OpenID4VCITokenRequestDTO, OpenID4VCITokenResponseDTO,
    Timestamp,
};
use crate::provider::issuance_protocol::openid4vci_draft13::proof_formatter::OpenID4VCIProofJWTFormatter;
use crate::provider::issuance_protocol::openid4vci_draft13::service::{
    create_credential_offer, create_issuer_metadata_response, create_service_discovery_response,
    get_credential_schema_base_url, oidc_issuer_create_token, parse_access_token,
    parse_refresh_token,
};
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError,
};
use crate::service::oid4vci_draft13::mapper::interaction_data_to_dto;
use crate::service::oid4vci_draft13::validator::{
    throw_if_access_token_invalid, throw_if_credential_request_invalid,
    validate_config_entity_presence,
};
use crate::service::ssi_validator::validate_issuance_protocol_type;
use crate::util::key_verification::KeyVerification;
use crate::util::oidc::map_to_openid4vp_format;

impl OID4VCIDraft13Service {
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
        let base_url = get_credential_schema_base_url(credential_schema_id, protocol_base_url);

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
            .get_formatter(&schema.format)
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
            &base_url,
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
            .get_fields(&credential.exchange)?
            .r#type;

        if issuance_protocol_type != IssuanceProtocolType::OpenId4VciDraft13 {
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
            .wallet_storage_type
            .clone();

        let claims = credential
            .claims
            .ok_or(ServiceError::MappingError("claims missing".to_string()))?
            .iter()
            .map(|claim| claim.to_owned())
            .collect::<Vec<_>>();

        let credential_subject = credentials_format(wallet_storage_type, &claims)
            .map_err(|e| ServiceError::MappingError(e.to_string()))?;

        Ok(create_credential_offer(
            url,
            &interaction.id.to_string(),
            credential
                .issuer_identifier
                .ok_or(ServiceError::MappingError(
                    "issuer_identifier missing".to_string(),
                ))?
                .did
                .ok_or(ServiceError::MappingError("issuer did missing".to_string()))?
                .did,
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
            .get_interaction(&interaction_id, &InteractionRelations::default())
            .await?
        else {
            return Err(
                BusinessLogicError::MissingInteractionForAccessToken { interaction_id }.into(),
            );
        };

        let interaction_data = interaction_data_to_dto(&interaction)?;
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

        validate_issuance_protocol_type(self.protocol_type, &self.config, &credential.exchange)?;

        let (holder_did, holder_identifier, holder_key_id) = if request.proof.proof_type == "jwt" {
            let (holder_did_value, key_id) = OpenID4VCIProofJWTFormatter::verify_proof(
                &request.proof.jwt,
                Box::new(KeyVerification {
                    key_algorithm_provider: self.key_algorithm_provider.clone(),
                    did_method_provider: self.did_method_provider.clone(),
                    key_role: KeyRole::Authentication,
                }),
                interaction_data.nonce,
            )
            .await
            .map_err(|_| ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidOrMissingProof))?;

            let (did, identifier) = get_or_create_did_and_identifier(
                &*self.did_method_provider,
                &*self.did_repository,
                &*self.identifier_repository,
                &schema.organisation,
                &holder_did_value,
                DidRole::Holder,
            )
            .await?;
            Ok((did, identifier, key_id))
        } else {
            Err(ServiceError::OpenID4VCIError(
                OpenID4VCIError::InvalidOrMissingProof,
            ))
        }?;

        self.credential_repository
            .update_credential(
                credential.id,
                UpdateCredentialRequest {
                    holder_identifier_id: Some(holder_identifier.id),
                    ..Default::default()
                },
            )
            .await?;

        let issued_credential = self
            .protocol_provider
            .get_protocol(&credential.exchange)
            .ok_or(ServiceError::MappingError(
                "issuance protocol not found".to_string(),
            ))?
            .issuer_issue_credential(&credential.id, holder_did, holder_identifier, holder_key_id)
            .await;

        match issued_credential {
            Ok(issued_credential) => Ok(issued_credential.into()),
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

        validate_issuance_protocol_type(self.protocol_type, &self.config, &credential.exchange)?;

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
            get_exchange_param_pre_authorization_expires_in(&self.config, &credential.exchange)?;
        let access_token_expires_in =
            get_exchange_param_token_expires_in(&self.config, &credential.exchange)?;
        let refresh_token_expires_in =
            get_exchange_param_refresh_token_expires_in(&self.config, &credential.exchange)?;

        let mut interaction_data = interaction_data_to_dto(&interaction)?;

        let mut response = oidc_issuer_create_token(
            &interaction_data,
            &convert_inner(credentials.to_owned()),
            &interaction,
            &request,
            pre_authorization_expires_in,
            access_token_expires_in,
            refresh_token_expires_in,
        )?;
        // add nonce to interaction data so we can check it when verifying the proof
        interaction_data.nonce = response.c_nonce.clone();

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
            if credential_schema.format == "MDOC" {
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
}

pub fn credentials_format(
    wallet_storage_type: Option<WalletStorageTypeEnum>,
    claims: &[Claim],
) -> Result<ExtendedSubjectDTO, OpenIDIssuanceError> {
    Ok(ExtendedSubjectDTO {
        wallet_storage_type,
        keys: Some(ExtendedSubjectClaimsDTO {
            claims: IndexMap::from_iter(claims.iter().filter_map(|claim| {
                claim.schema.as_ref().map(|schema| {
                    (
                        claim.path.clone(),
                        OpenID4VCICredentialValueDetails {
                            value: claim.value.clone(),
                            value_type: schema.data_type.clone(),
                        },
                    )
                })
            })),
        }),
    })
}

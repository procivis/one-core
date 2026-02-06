use std::str::FromStr;

use futures::FutureExt;
use futures::future::BoxFuture;
use one_crypto::utilities;
use one_dto_mapper::convert_inner;
use secrecy::SecretString;
use shared_types::{CredentialId, CredentialSchemaId, InteractionId};
use standardized_types::oauth2::dynamic_client_registration::TokenEndpointAuthMethod;
use time::OffsetDateTime;
use uuid::Uuid;

use super::OID4VCIFinal1_0Service;
use super::dto::{OpenID4VCICredentialResponseDTO, OpenID4VCICredentialResponseEntryDTO};
use super::mapper::interaction_data_to_dto;
use super::nonce::{generate_nonce, validate_nonce};
use super::validator::{
    self, extract_wallet_metadata, throw_if_access_token_invalid,
    throw_if_credential_request_invalid, validate_pop_audience, validate_timestamps,
    verify_pop_signature, verify_wia_signature, verify_wua_wia_issuers_match,
};
use crate::config::ConfigValidationError;
use crate::config::core_config::{FormatType, IssuanceProtocolType};
use crate::mapper::exchange::{
    get_exchange_param_pre_authorization_expires_in, get_exchange_param_refresh_token_expires_in,
    get_exchange_param_token_expires_in,
};
use crate::model::blob::{Blob, BlobType};
use crate::model::certificate::CertificateRelations;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::common::LockType;
use crate::model::credential::{
    Credential, CredentialRelations, CredentialStateEnum, UpdateCredentialRequest,
};
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaRelations};
use crate::model::did::{DidRelations, KeyRole};
use crate::model::identifier::{Identifier, IdentifierRelations};
use crate::model::interaction::{InteractionRelations, UpdateInteractionRequest};
use crate::model::organisation::OrganisationRelations;
use crate::proto::identifier_creator::{IdentifierRole, RemoteIdentifierRelation};
use crate::proto::jwt::Jwt;
use crate::proto::key_verification::KeyVerification;
use crate::proto::transaction_manager::IsolationLevel;
use crate::proto::wallet_unit::WalletUnitStatusCheckResponse;
use crate::provider::blob_storage_provider::BlobStorageType;
use crate::provider::credential_formatter::model::IdentifierDetails;
use crate::provider::issuance_protocol::error::{
    IssuanceProtocolError, OpenID4VCIError, OpenIDIssuanceError,
};
use crate::provider::issuance_protocol::openid4vci_final1_0::mapper::{
    map_cryptographic_binding_methods_supported, map_proof_types_supported,
};
use crate::provider::issuance_protocol::openid4vci_final1_0::model::{
    OAuthAuthorizationServerMetadata, OpenID4VCICredentialRequestDTO,
    OpenID4VCICredentialRequestProofs, OpenID4VCIFinal1CredentialOfferDTO, OpenID4VCIFinal1Params,
    OpenID4VCIIssuerInteractionDataDTO, OpenID4VCIIssuerMetadataResponseDTO,
    OpenID4VCINonceResponseDTO, OpenID4VCINotificationEvent, OpenID4VCINotificationRequestDTO,
    OpenID4VCITokenRequestDTO, OpenID4VCITokenResponseDTO, Timestamp,
};
use crate::provider::issuance_protocol::openid4vci_final1_0::proof_formatter::{
    OpenID4VCIProofHolderBinding, OpenID4VCIProofJWTFormatter, OpenID4VCIVerifiedProof,
};
use crate::provider::issuance_protocol::openid4vci_final1_0::service::{
    create_credential_offer, create_issuer_metadata_response, oidc_issuer_create_token,
    parse_access_token, parse_refresh_token,
};
use crate::provider::revocation::model::{Operation, RevocationState};
use crate::repository::error::DataLayerError;
use crate::service::credential::dto::{WalletInstanceAttestationDTO, WalletUnitAttestationDTO};
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError,
};
use crate::service::oid4vci_final1_0::dto::OAuthAuthorizationServerMetadataResponseDTO;
use crate::service::ssi_validator::validate_issuance_protocol_type;
use crate::service::wallet_provider::dto::WalletInstanceAttestationClaims;
use crate::validator::throw_if_credential_state_not_eq;

impl OID4VCIFinal1_0Service {
    pub async fn get_issuer_metadata(
        &self,
        protocol_id: &str,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<OpenID4VCIIssuerMetadataResponseDTO, ServiceError> {
        validate_issuance_protocol_type(
            IssuanceProtocolType::OpenId4VciFinal1_0,
            &self.config,
            protocol_id,
        )?;

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
        let oidc_format = match &format_type {
            FormatType::Jwt => "jwt_vc_json",
            FormatType::SdJwt => "vc+sd-jwt",
            FormatType::SdJwtVc => "dc+sd-jwt",
            FormatType::JsonLdClassic | FormatType::JsonLdBbsPlus => "ldp_vc",
            FormatType::Mdoc => "mso_mdoc",
            FormatType::PhysicalCard => {
                return Err(OpenID4VCIError::UnsupportedCredentialFormat.into());
            }
        }
        .to_string();

        let formatter = self
            .formatter_provider
            .get_credential_formatter(&schema.format)
            .ok_or(MissingProviderError::Formatter(schema.format.to_string()))?;

        let format_capabilities = formatter.get_capabilities();
        let credential_signing_alg_values_supported = format_capabilities
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
            protocol_id,
            &oidc_format,
            &schema,
            map_cryptographic_binding_methods_supported(
                &self.did_method_provider.supported_method_names(),
                &format_capabilities.holder_identifier_types,
            ),
            Some(map_proof_types_supported(
                self.key_algorithm_provider
                    .supported_verification_jose_alg_ids(),
                schema.key_storage_security.map(|x| x.into()),
            )),
            credential_signing_alg_values_supported,
        )
        .map_err(Into::into)
    }

    pub async fn oauth_authorization_server(
        &self,
        protocol_id: &str,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<OAuthAuthorizationServerMetadataResponseDTO, ServiceError> {
        validate_issuance_protocol_type(
            IssuanceProtocolType::OpenId4VciFinal1_0,
            &self.config,
            protocol_id,
        )?;

        let protocol_base_url = self
            .protocol_base_url
            .as_ref()
            .ok_or(ServiceError::Other("Missing base_url".to_owned()))?;

        let Some(credential_schema) = self
            .credential_schema_repository
            .get_credential_schema(
                credential_schema_id,
                &CredentialSchemaRelations {
                    ..Default::default()
                },
            )
            .await?
        else {
            return Err(EntityNotFoundError::CredentialSchema(*credential_schema_id).into());
        };

        let token_endpoint_auth_methods_supported =
            if credential_schema.requires_wallet_instance_attestation {
                vec![TokenEndpointAuthMethod::AttestJwtClientAuth]
            } else {
                vec![TokenEndpointAuthMethod::None]
            };

        // Per https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-07#section-10.1
        // If token_endpoint_auth_methods_supported includes attest_jwt_client_auth, we MUST include these fields
        let (
            client_attestation_signing_alg_values_supported,
            client_attestation_pop_signing_alg_values_supported,
        ) = if token_endpoint_auth_methods_supported
            .contains(&TokenEndpointAuthMethod::AttestJwtClientAuth)
        {
            (
                Some(vec!["ES256".to_string()]),
                Some(vec!["ES256".to_string()]),
            )
        } else {
            (None, None)
        };

        let credential_issuer = format!("{protocol_base_url}/{protocol_id}/{credential_schema_id}");

        Ok(OAuthAuthorizationServerMetadata {
            issuer: credential_issuer
                .parse()
                .map_err(|e| ServiceError::MappingError(format!("Invalid issuer URL: {e}")))?,
            authorization_endpoint: Some(
                // ONE-8318: required in iOS EUDI wallet
                format!("{protocol_base_url}/{credential_schema_id}/authorize")
                    .parse()
                    .map_err(|e| {
                        ServiceError::MappingError(format!(
                            "Invalid authorization endpoint URL: {e}"
                        ))
                    })?,
            ),
            token_endpoint: Some(
                format!("{protocol_base_url}/{credential_schema_id}/token")
                    .parse()
                    .map_err(|e| {
                        ServiceError::MappingError(format!("Invalid token endpoint URL: {e}"))
                    })?,
            ),
            jwks_uri: None,
            pushed_authorization_request_endpoint: None,
            code_challenge_methods_supported: vec![],
            scopes_supported: vec!["openid".to_string()],
            response_types_supported: vec!["code".to_string(), "token".to_string()],
            grant_types_supported: vec![
                "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
                "refresh_token".to_string(),
            ],
            token_endpoint_auth_methods_supported,
            challenge_endpoint: None,
            client_attestation_signing_alg_values_supported,
            client_attestation_pop_signing_alg_values_supported,
            dpop_signing_alg_values_supported: Some(vec!["ES256".to_string()]), // necessary for the EUDI wallet to work
        }
        .into())
    }

    pub async fn get_credential_offer(
        &self,
        credential_schema_id: CredentialSchemaId,
        credential_id: CredentialId,
    ) -> Result<OpenID4VCIFinal1CredentialOfferDTO, ServiceError> {
        let credential = self
            .credential_repository
            .get_credential(
                &credential_id,
                &CredentialRelations {
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

        validate_issuance_protocol_type(
            IssuanceProtocolType::OpenId4VciFinal1_0,
            &self.config,
            &credential.protocol,
        )?;

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

        let protocol_base_url = self
            .protocol_base_url
            .as_ref()
            .ok_or(ServiceError::Other("Missing base_url".to_owned()))?;

        Ok(create_credential_offer(
            protocol_base_url,
            &credential.protocol,
            &interaction.id.to_string(),
            credential_schema,
        )?)
    }

    pub async fn create_credential(
        &self,
        credential_schema_id: &CredentialSchemaId,
        access_token: &str,
        request: OpenID4VCICredentialRequestDTO,
    ) -> Result<OpenID4VCICredentialResponseDTO, ServiceError> {
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
                None,
            )
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

        let token_verifier = KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::Authentication,
            certificate_validator: self.certificate_validator.clone(),
        };

        let OpenID4VCIVerifiedProof {
            holder_binding,
            nonce,
            key_attestation,
        } = OpenID4VCIProofJWTFormatter::verify_proof(jwt, &token_verifier)
            .await
            .map_err(|err| {
                tracing::debug!("holder proof validation failed: {err}");
                ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidOrMissingProof)
            })?;

        let nonce = nonce.ok_or(OpenID4VCIError::InvalidNonce)?;
        let params: OpenID4VCIFinal1Params =
            self.config.issuance_protocol.get(&credential.protocol)?;

        let Some(nonce_params) = &params.nonce else {
            return Err(ConfigValidationError::TypeNotFound(credential.protocol.to_owned()).into());
        };

        let nonce_id =
            validate_nonce(nonce_params, self.base_url.to_owned(), &nonce).map_err(|e| {
                tracing::debug!("Nonce validation failed: {e}");
                OpenID4VCIError::InvalidNonce
            })?;

        self.interaction_repository
            .mark_nonce_as_used(&interaction.id, nonce_id.into())
            .await
            .map_err(|e| match e {
                DataLayerError::RecordNotUpdated | DataLayerError::AlreadyExists => {
                    ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidNonce)
                }
                e => ServiceError::Repository(e),
            })?;

        // Key attestation is expected if wallet storage type is set
        if let Some(key_storage_security) = schema.key_storage_security {
            let Some(key_attestation_jwt) = &key_attestation else {
                tracing::debug!("expected key attestation but none provided");
                return Err(ServiceError::OpenID4VCIError(
                    OpenID4VCIError::InvalidOrMissingProof,
                ));
            };

            let attested_keys = validator::validate_key_attestation(
                key_attestation_jwt,
                &token_verifier,
                key_storage_security.into(),
                params.key_attestation_leeway,
            )
            .await?;

            let wallet_unit_attestation_status = self
                .holder_wallet_unit_proto
                .check_wallet_unit_attestation_status(key_attestation_jwt)
                .await?;

            if wallet_unit_attestation_status == WalletUnitStatusCheckResponse::Revoked {
                tracing::error!("wallet unit attestation is revoked");
                return Err(ServiceError::OpenID4VCIError(
                    OpenID4VCIError::InvalidOrMissingProof,
                ));
            }

            if schema.requires_wallet_instance_attestation {
                let Some(wallet_instance_attestation_blob_id) =
                    &credential.wallet_instance_attestation_blob_id
                else {
                    tracing::debug!(
                        "app attestation required but no wallet app attestation blob ID found"
                    );
                    return Err(ServiceError::OpenID4VCIError(
                        OpenID4VCIError::InvalidOrMissingProof,
                    ));
                };

                let db_blob_storage = self
                    .blob_storage_provider
                    .get_blob_storage(BlobStorageType::Db)
                    .await
                    .ok_or_else(|| {
                        MissingProviderError::BlobStorage(BlobStorageType::Db.to_string())
                    })?;

                let wallet_instance_attestation_blob = db_blob_storage
                    .get(wallet_instance_attestation_blob_id)
                    .await?
                    .ok_or(ServiceError::MappingError(
                        "wallet app attestation blob is None".to_string(),
                    ))?;

                let wia_dto: WalletInstanceAttestationDTO = serde_json::from_slice(
                    &wallet_instance_attestation_blob.value,
                )
                .map_err(|e| {
                    ServiceError::MappingError(format!("Failed to deserialize WIA blob: {e}"))
                })?;

                let wia =
                    Jwt::<WalletInstanceAttestationClaims>::decompose_token(&wia_dto.attestation)?;

                verify_wua_wia_issuers_match(key_attestation_jwt, &wia)?;
            }

            let proof_signing_key = match &holder_binding {
                OpenID4VCIProofHolderBinding::Did { did, key_id } => {
                    let did_document =
                        self.did_method_provider.resolve(did).await.map_err(|e| {
                            tracing::debug!("failed to resolve DID for key attestation check: {e}");
                            ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidOrMissingProof)
                        })?;

                    did_document
                        .find_verification_method(Some(key_id), Some(KeyRole::Authentication))
                        .map(|vm| vm.public_key_jwk.clone())
                        .ok_or_else(|| {
                            tracing::debug!(
                                "missing verification method for key attestation check: {key_id}"
                            );
                            ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidOrMissingProof)
                        })?
                }
                OpenID4VCIProofHolderBinding::Jwk(jwk) => jwk.clone(),
            };

            if !attested_keys.contains(&proof_signing_key) {
                tracing::debug!("proof signing key is not in the attested_keys list");
                return Err(ServiceError::OpenID4VCIError(
                    OpenID4VCIError::InvalidOrMissingProof,
                ));
            }
        } else if key_attestation.is_some() {
            // Key attestation provided but not required
            tracing::debug!("key attestation provided but not required");
            return Err(ServiceError::OpenID4VCIError(
                OpenID4VCIError::InvalidOrMissingProof,
            ));
        }

        let (holder_identifier, holder_key_id) = match holder_binding {
            OpenID4VCIProofHolderBinding::Did { did, key_id } => {
                let (identifier, _) = self
                    .identifier_creator
                    .get_or_create_remote_identifier(
                        &schema.organisation,
                        &IdentifierDetails::Did(did),
                        IdentifierRole::Holder,
                    )
                    .await?;
                (identifier, key_id)
            }
            OpenID4VCIProofHolderBinding::Jwk(jwk) => {
                let (identifier, RemoteIdentifierRelation::Key(key)) = self
                    .identifier_creator
                    .get_or_create_remote_identifier(
                        &schema.organisation,
                        &IdentifierDetails::Key(jwk),
                        IdentifierRole::Holder,
                    )
                    .await?
                else {
                    return Err(ServiceError::MappingError(
                        "Invalid identifier type".to_string(),
                    ));
                };

                (identifier, key.id.to_string())
            }
        };

        let result = self
            .transaction_manager
            .tx_with_config(
                self.issue_tx(
                    interaction_id,
                    holder_identifier,
                    holder_key_id,
                    credential,
                    key_attestation,
                )
                .boxed(),
                Some(IsolationLevel::ReadCommitted),
                None,
            )
            .await??;
        tracing::info!("Issued credential {}", credential.id);
        Ok(result)
    }

    async fn issue_tx(
        &self,
        interaction_id: InteractionId,
        holder_identifier: Identifier,
        holder_key_id: String,
        credential: &Credential,
        key_attestation: Option<String>,
    ) -> Result<OpenID4VCICredentialResponseDTO, ServiceError> {
        // Lock interaction, so that the issuance process is done only by one thread
        let Some(interaction) = self
            .interaction_repository
            .get_interaction(
                &interaction_id,
                &InteractionRelations {
                    organisation: Some(Default::default()),
                },
                Some(LockType::Update),
            )
            .await?
        else {
            return Err(
                BusinessLogicError::MissingInteractionForAccessToken { interaction_id }.into(),
            );
        };
        let mut interaction_data = interaction_data_to_dto(&interaction)?;

        let wua_blob_id = if let Some(attestation) = key_attestation {
            let blob_storage = self
                .blob_storage_provider
                .get_blob_storage(BlobStorageType::Db)
                .await
                .ok_or(MissingProviderError::BlobStorage(
                    BlobStorageType::Db.to_string(),
                ))?;

            let wua_dto = serde_json::to_vec(&WalletUnitAttestationDTO { attestation })
                .map_err(|e| ServiceError::MappingError(e.to_string()))?;
            let wua_blob = Blob::new(wua_dto, BlobType::WalletUnitAttestation);
            blob_storage.create(wua_blob.clone()).await?;
            Some(wua_blob.id)
        } else {
            None
        };
        let holder_identifier_id = holder_identifier.id;
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
                self.credential_repository
                    .update_credential(
                        credential.id,
                        UpdateCredentialRequest {
                            issuance_date: Some(OffsetDateTime::now_utc()),
                            holder_identifier_id: Some(holder_identifier_id),
                            wallet_unit_attestation_blob_id: wua_blob_id,
                            ..Default::default()
                        },
                    )
                    .await?;
                if let Some(notification_id) = &issued_credential.notification_id {
                    interaction_data.notification_id = Some(notification_id.to_owned());

                    let data = serde_json::to_vec(&interaction_data)
                        .map_err(|e| ServiceError::MappingError(e.to_string()))?;

                    self.interaction_repository
                        .update_interaction(
                            interaction.id,
                            UpdateInteractionRequest {
                                data: Some(Some(data)),
                            },
                        )
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
        let interaction_id = parse_access_token(access_token)?;
        let Some(interaction) = self
            .interaction_repository
            .get_interaction(&interaction_id, &InteractionRelations::default(), None)
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
                    issuer_certificate: Some(Default::default()),
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

        validate_issuance_protocol_type(
            IssuanceProtocolType::OpenId4VciFinal1_0,
            &self.config,
            &credential.protocol,
        )?;

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

        let success_log = format!(
            "Processed notification for credential {}: event `{}`, description: `{:?}`",
            credential.id, request.event, request.event_description
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

        let revocation_method = match &schema.revocation_method {
            Some(method_id) => Some(
                self.revocation_method_provider
                    .get_revocation_method(method_id)
                    .ok_or(MissingProviderError::RevocationMethod(method_id.clone()))?,
            ),
            None => None,
        };

        self.credential_repository
            .update_credential(
                credential.id,
                UpdateCredentialRequest {
                    state: Some(new_state),
                    ..Default::default()
                },
            )
            .await?;

        // mark the credential as revoked (if supported and not done before)
        if matches!(
            credential.state,
            CredentialStateEnum::Accepted | CredentialStateEnum::Suspended
        ) && let Some(revocation_method) = revocation_method
            && revocation_method
                .get_capabilities()
                .operations
                .contains(&Operation::Revoke)
        {
            revocation_method
                .mark_credential_as(credential, RevocationState::Revoked)
                .await?;
        }
        tracing::info!(message = success_log);
        Ok(())
    }

    pub async fn create_token(
        &self,
        credential_schema_id: &CredentialSchemaId,
        request: OpenID4VCITokenRequestDTO,
        oauth_client_attestation: Option<&str>,
        oauth_client_attestation_pop: Option<&str>,
    ) -> Result<OpenID4VCITokenResponseDTO, ServiceError> {
        let params = validator::get_config_entity(&self.config)?;

        let credential_schema = self
            .credential_schema_repository
            .get_credential_schema(credential_schema_id, &CredentialSchemaRelations::default())
            .await?
            .ok_or(EntityNotFoundError::CredentialSchema(*credential_schema_id))?;

        let interaction_id = match &request {
            OpenID4VCITokenRequestDTO::PreAuthorizedCode {
                pre_authorized_code,
                tx_code: _,
            } => Uuid::from_str(pre_authorized_code)
                .map_err(|_| {
                    ServiceError::OpenIDIssuanceError(OpenIDIssuanceError::OpenID4VCI(
                        OpenID4VCIError::InvalidRequest,
                    ))
                })?
                .into(),
            OpenID4VCITokenRequestDTO::AuthorizationCode { .. } => {
                return Err(ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidGrant));
            }
            OpenID4VCITokenRequestDTO::RefreshToken { refresh_token } => {
                parse_refresh_token(refresh_token)?
            }
        };

        let credentials = self
            .credential_repository
            .get_credentials_by_interaction_id(&interaction_id, &CredentialRelations::default())
            .await?;

        let credential = credentials
            .first()
            .ok_or(BusinessLogicError::MissingCredentialsForInteraction { interaction_id })?;

        validate_issuance_protocol_type(
            IssuanceProtocolType::OpenId4VciFinal1_0,
            &self.config,
            &credential.protocol,
        )?;

        let wallet_instance_attestation_token = self
            .validate_oauth_client_attestation(
                oauth_client_attestation,
                oauth_client_attestation_pop,
                &credential_schema,
                &credential.protocol,
                params.oauth_attestation_leeway,
            )
            .await?;

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

        let tx: BoxFuture<Result<_, ServiceError>> = async {
            // Lock the interaction to ensure exclusive access
            let mut interaction = self
                .interaction_repository
                .get_interaction(
                    &interaction_id,
                    &InteractionRelations::default(),
                    Some(LockType::Update),
                )
                .await?
                .ok_or(ServiceError::MappingError(format!(
                    "Interaction `{}` not found",
                    interaction_id
                )))?;
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

            for credential in &credentials {
                // If a wallet instance attestation token is provided, we create a new blob and update the credential
                let wallet_instance_attestation_blob_id =
                    match wallet_instance_attestation_token.clone() {
                        Some(wallet_instance_attestation_token) => {
                            let blob_storage = self
                                .blob_storage_provider
                                .get_blob_storage(BlobStorageType::Db)
                                .await
                                .ok_or(MissingProviderError::BlobStorage(
                                    BlobStorageType::Db.to_string(),
                                ))?;

                            let attestation_token =
                                serde_json::to_vec(&wallet_instance_attestation_token)
                                    .map_err(|e| ServiceError::MappingError(e.to_string()))?;

                            let blob =
                                Blob::new(attestation_token, BlobType::WalletInstanceAttestation);

                            blob_storage.create(blob.clone()).await?;
                            Some(blob.id)
                        }
                        None => None,
                    };

                let mut state_update = UpdateCredentialRequest {
                    wallet_instance_attestation_blob_id,
                    ..Default::default()
                };

                if let OpenID4VCITokenRequestDTO::PreAuthorizedCode { .. } = &request {
                    state_update.state = Some(CredentialStateEnum::Offered);
                }

                // Only update the credential if there is a change
                if state_update.wallet_instance_attestation_blob_id.is_some()
                    || state_update.state.is_some()
                {
                    self.credential_repository
                        .update_credential(credential.id, state_update)
                        .await?;
                }
            }

            let credential_format_type = self
                .config
                .format
                .get_fields(&credential_schema.format)?
                .r#type;

            // we add refresh token for mdoc
            if credential_format_type == FormatType::Mdoc {
                response.refresh_token = Some(generate_new_token());
                response.refresh_token_expires_in =
                    Some(Timestamp((now + refresh_token_expires_in).unix_timestamp()));
            }

            let interaction_data: OpenID4VCIIssuerInteractionDataDTO = (&response).try_into()?;
            let data = serde_json::to_vec(&interaction_data)
                .map_err(|e| ServiceError::MappingError(e.to_string()))?;
            interaction.data = Some(data);

            self.interaction_repository
                .update_interaction(interaction.id, interaction.into())
                .await?;
            Ok(response)
        }
        .boxed();
        let result = self.transaction_manager.tx(tx).await??;
        tracing::info!(
            "Issued access token for issuance of credential {}",
            credential.id
        );
        Ok(result)
    }

    async fn validate_oauth_client_attestation(
        &self,
        oauth_client_attestation: Option<&str>,
        oauth_client_attestation_pop: Option<&str>,
        credential_schema: &CredentialSchema,
        protocol_id: &str,
        leeway: u64,
    ) -> Result<Option<WalletInstanceAttestationDTO>, ServiceError> {
        // If the credential schema does not require client attestation, no tokens are expected
        if !credential_schema.requires_wallet_instance_attestation {
            if oauth_client_attestation.is_some() || oauth_client_attestation_pop.is_some() {
                return Err(ServiceError::OpenID4VCIError(
                    OpenID4VCIError::InvalidRequest,
                ));
            }
            return Ok(None);
        }

        // Parse tokens
        let wallet_instance_attestation_token = oauth_client_attestation.ok_or(
            ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidRequest),
        )?;
        let proof_of_key_possesion_token = oauth_client_attestation_pop.ok_or(
            ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidRequest),
        )?;

        let wallet_instance_attestation = Jwt::<WalletInstanceAttestationClaims>::decompose_token(
            wallet_instance_attestation_token,
        )?;
        let proof_of_key_possession = Jwt::<()>::decompose_token(proof_of_key_possesion_token)?;

        // Validate timestamps for both tokens
        validate_timestamps(&wallet_instance_attestation, leeway)?;
        validate_timestamps(&proof_of_key_possession, leeway)?;

        // Validate proof of possession audience
        let expected_audience = self
            .protocol_base_url
            .as_ref()
            .map(|base_url| format!("{base_url}/{protocol_id}/{}", credential_schema.id))
            .ok_or(ServiceError::OpenID4VCIError(
                OpenID4VCIError::InvalidRequest,
            ))?;
        validate_pop_audience(&proof_of_key_possession, &expected_audience)?;

        // Verify signatures
        verify_pop_signature(
            &proof_of_key_possession,
            &wallet_instance_attestation,
            self.key_algorithm_provider.as_ref(),
        )?;

        let verifier = KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
            certificate_validator: self.certificate_validator.clone(),
        };

        verify_wia_signature(&wallet_instance_attestation, &verifier).await?;

        // Extract wallet metadata
        let (name, link) = extract_wallet_metadata(&wallet_instance_attestation)?;

        Ok(Some(WalletInstanceAttestationDTO {
            name,
            link,
            attestation: wallet_instance_attestation_token.to_owned(),
        }))
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

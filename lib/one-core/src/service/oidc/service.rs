use std::str::FromStr;

use anyhow::Context;
use indexmap::IndexMap;
use one_crypto::jwe::{decrypt_jwe_payload, extract_jwe_header};
use one_crypto::utilities;
use one_dto_mapper::convert_inner;
use shared_types::{CredentialId, CredentialSchemaId, DidValue, KeyId, ProofId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::OpenID4VCICredentialResponseDTO;
use super::mapper::credential_from_proved;
use super::proof_request::{
    generate_authorization_request_client_id_scheme_did,
    generate_authorization_request_client_id_scheme_redirect_uri,
    generate_authorization_request_client_id_scheme_verifier_attestation,
    generate_authorization_request_client_id_scheme_x509_san_dns,
};
use super::OIDCService;
use crate::common_mapper::{
    encode_cbor_base64, get_encryption_key_jwk_from_proof,
    get_exchange_param_pre_authorization_expires_in, get_exchange_param_refresh_token_expires_in,
    get_exchange_param_token_expires_in, get_or_create_did, DidRole,
};
use crate::common_validator::{
    throw_if_credential_state_not_eq, throw_if_latest_proof_state_not_eq,
};
use crate::config::core_config::{ExchangeType, TransportType};
use crate::model::claim::{Claim, ClaimRelations};
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential::{
    Clearable, CredentialRelations, CredentialStateEnum, UpdateCredentialRequest,
};
use crate::model::credential_schema::{CredentialSchemaRelations, WalletStorageTypeEnum};
use crate::model::did::DidRelations;
use crate::model::history::HistoryErrorMetadata;
use crate::model::interaction::InteractionRelations;
use crate::model::key::KeyRelations;
use crate::model::organisation::OrganisationRelations;
use crate::model::proof::{Proof, ProofRelations, ProofStateEnum, UpdateProofRequest};
use crate::model::proof_schema::{
    ProofInputSchemaRelations, ProofSchemaClaimRelations, ProofSchemaRelations,
};
use crate::model::validity_credential::Mdoc;
use crate::provider::exchange_protocol::error::ExchangeProtocolError;
use crate::provider::exchange_protocol::openid4vc::error::{OpenID4VCError, OpenID4VCIError};
use crate::provider::exchange_protocol::openid4vc::mapper::create_open_id_for_vp_formats;
use crate::provider::exchange_protocol::openid4vc::model::{
    ClientIdSchemaType, ExtendedSubjectClaimsDTO, ExtendedSubjectDTO, JwePayload,
    OpenID4VCICredentialOfferDTO, OpenID4VCICredentialRequestDTO, OpenID4VCICredentialValueDetails,
    OpenID4VCIDiscoveryResponseDTO, OpenID4VCIIssuerMetadataResponseDTO, OpenID4VCITokenRequestDTO,
    OpenID4VCITokenResponseDTO, OpenID4VPClientMetadata, OpenID4VPDirectPostRequestDTO,
    OpenID4VPDirectPostResponseDTO, OpenID4VPPresentationDefinition,
    OpenID4VPVerifierInteractionContent, RequestData,
};
use crate::provider::exchange_protocol::openid4vc::openidvc_ble::model::BLEOpenID4VPInteractionData;
use crate::provider::exchange_protocol::openid4vc::openidvc_mqtt::model::MQTTOpenID4VPInteractionDataVerifier;
use crate::provider::exchange_protocol::openid4vc::proof_formatter::OpenID4VCIProofJWTFormatter;
use crate::provider::exchange_protocol::openid4vc::service::{
    create_credential_offer, create_issuer_metadata_response,
    create_open_id_for_vp_client_metadata, create_service_discovery_response,
    get_credential_schema_base_url, parse_access_token, parse_refresh_token,
};
use crate::provider::key_storage::error::KeyStorageError;
use crate::service::error::ErrorCode::BR_0000;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError,
};
use crate::service::oidc::mapper::{interaction_data_to_dto, parse_interaction_content};
use crate::service::oidc::validator::{
    throw_if_credential_request_invalid, throw_if_interaction_data_invalid,
    validate_config_entity_presence,
};
use crate::service::ssi_validator::validate_exchange_type;
use crate::util::oidc::{map_core_to_oidc_format, map_from_oidc_format_to_core_detailed};

impl OIDCService {
    pub async fn oidc_issuer_get_issuer_metadata(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<OpenID4VCIIssuerMetadataResponseDTO, ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let core_base_url = self
            .core_base_url
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "Host URL not specified".to_string(),
            ))?;

        let base_url = get_credential_schema_base_url(credential_schema_id, core_base_url)?;

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

        let oidc_format = map_core_to_oidc_format(&schema.format).map_err(ServiceError::from)?;

        create_issuer_metadata_response(&base_url, &oidc_format, &schema, &self.config)
            .map_err(Into::into)
    }

    pub async fn oidc_verifier_get_client_request(
        &self,
        id: ProofId,
    ) -> Result<String, ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let proof = self
            .proof_repository
            .get_proof(
                &id,
                &ProofRelations {
                    interaction: Some(Default::default()),
                    verifier_did: Some(DidRelations {
                        keys: Some(KeyRelations::default()),
                        ..Default::default()
                    }),
                    verifier_key: Some(Default::default()),
                    schema: Some(ProofSchemaRelations {
                        proof_inputs: Some(ProofInputSchemaRelations {
                            credential_schema: Some(Default::default()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(ServiceError::EntityNotFound(EntityNotFoundError::Proof(id)))?;

        throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Pending)?;
        validate_exchange_type(ExchangeType::OpenId4Vc, &self.config, &proof.exchange)?;

        let interaction = proof
            .interaction
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "missing proof interaction".to_string(),
            ))?;

        let interaction_data: OpenID4VPVerifierInteractionContent =
            parse_interaction_content(interaction.data.as_ref())
                .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        let client_id_scheme =
            interaction_data
                .client_id_scheme
                .ok_or(ExchangeProtocolError::Failed(
                    "missing client_id_scheme".to_string(),
                ))?;
        Ok(match client_id_scheme {
            ClientIdSchemaType::RedirectUri => {
                generate_authorization_request_client_id_scheme_redirect_uri(
                    &proof,
                    interaction_data,
                    &interaction.id,
                    &*self.key_algorithm_provider,
                )
                .await?
            }
            ClientIdSchemaType::VerifierAttestation => {
                generate_authorization_request_client_id_scheme_verifier_attestation(
                    &proof,
                    interaction_data,
                    &interaction.id,
                    &self.key_algorithm_provider,
                    &*self.key_provider,
                    &*self.did_method_provider,
                )
                .await?
            }
            ClientIdSchemaType::Did => {
                generate_authorization_request_client_id_scheme_did(
                    &proof,
                    interaction_data,
                    &interaction.id,
                    &self.key_algorithm_provider,
                    &*self.key_provider,
                )
                .await?
            }
            ClientIdSchemaType::X509SanDns => {
                generate_authorization_request_client_id_scheme_x509_san_dns(
                    &proof,
                    interaction_data,
                    &interaction.id,
                    &self.key_algorithm_provider,
                    &*self.key_provider,
                )
                .await?
            }
        })
    }

    pub async fn oidc_verifier_get_client_metadata(
        &self,
        id: ProofId,
    ) -> Result<OpenID4VPClientMetadata, ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let proof = self
            .proof_repository
            .get_proof(
                &id,
                &ProofRelations {
                    verifier_did: Some(DidRelations {
                        keys: Some(KeyRelations::default()),
                        ..Default::default()
                    }),
                    verifier_key: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(ServiceError::EntityNotFound(EntityNotFoundError::Proof(id)))?;

        throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Pending)?;
        validate_exchange_type(ExchangeType::OpenId4Vc, &self.config, &proof.exchange)?;

        let formats = create_open_id_for_vp_formats();
        let jwk = get_encryption_key_jwk_from_proof(&proof, &*self.key_algorithm_provider)?;

        Ok(create_open_id_for_vp_client_metadata(
            jwk.key_id,
            jwk.jwk.into(),
            formats,
            ClientIdSchemaType::RedirectUri,
        ))
    }

    pub async fn oidc_issuer_service_discovery(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<OpenID4VCIDiscoveryResponseDTO, ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let core_base_url = self
            .core_base_url
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

        let schema_base_url = get_credential_schema_base_url(&schema.id, core_base_url)?;

        Ok(create_service_discovery_response(&schema_base_url)?)
    }

    pub async fn oidc_issuer_get_credential_offer(
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
                    issuer_did: Some(DidRelations::default()),
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

        if credential.exchange != "OPENID4VC" {
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

        let url = get_url(self.core_base_url.to_owned())?;

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
            &url,
            &interaction.id.to_string(),
            credential
                .issuer_did
                .ok_or(ServiceError::MappingError("issuer did missing".to_string()))?
                .did,
            &credential_schema_id,
            &credential_schema.schema_id,
            credential_subject,
        )?)
    }

    pub async fn oidc_issuer_create_credential(
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

        throw_if_interaction_data_invalid(&interaction_data_to_dto(&interaction)?, access_token)?;

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

        validate_exchange_type(ExchangeType::OpenId4Vc, &self.config, &credential.exchange)?;

        let (holder_did, holder_key_id) = if request.proof.proof_type == "jwt" {
            let jwt = OpenID4VCIProofJWTFormatter::verify_proof(&request.proof.jwt).await?;
            let key_id = jwt.header.key_id.ok_or(ServiceError::OpenID4VCIError(
                OpenID4VCIError::InvalidOrMissingProof,
            ))?;
            let holder_did_value = DidValue::from_did_url(key_id.clone()).map_err(|_| {
                ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidOrMissingProof)
            })?;

            let did = get_or_create_did(
                &*self.did_repository,
                &schema.organisation,
                &holder_did_value,
                DidRole::Holder,
            )
            .await?;
            Ok((did, key_id))
        } else {
            Err(ServiceError::OpenID4VCIError(
                OpenID4VCIError::InvalidOrMissingProof,
            ))
        }?;

        self.credential_repository
            .update_credential(UpdateCredentialRequest {
                id: credential.id,
                holder_did_id: Some(holder_did.id),
                ..Default::default()
            })
            .await?;

        let issued_credential = self
            .protocol_provider
            .issue_credential(&credential.id, holder_did, holder_key_id)
            .await?;

        Ok(OpenID4VCICredentialResponseDTO {
            credential: issued_credential.credential,
            redirect_uri: credential.redirect_uri.to_owned(),
        })
    }

    pub async fn oidc_issuer_create_token(
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
                ServiceError::OpenID4VCError(OpenID4VCError::OpenID4VCI(
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

        validate_exchange_type(ExchangeType::OpenId4Vc, &self.config, &credential.exchange)?;

        let mut interaction = credential
            .interaction
            .clone()
            .ok_or(ServiceError::MappingError(
                "interaction is None".to_string(),
            ))?;

        // both refresh and access token have the same structure
        let generate_new_token = || {
            format!(
                "{}.{}",
                interaction_id,
                utilities::generate_alphanumeric(32)
            )
        };

        let pre_authorization_expires_in =
            get_exchange_param_pre_authorization_expires_in(&self.config, &credential.exchange)?;
        let access_token_expires_in =
            get_exchange_param_token_expires_in(&self.config, &credential.exchange)?;
        let refresh_token_expires_in =
            get_exchange_param_refresh_token_expires_in(&self.config, &credential.exchange)?;

        let mut interaction_data =
            crate::provider::exchange_protocol::openid4vc::service::oidc_issuer_create_token(
                interaction_data_to_dto(&interaction)?,
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
                    .update_credential(UpdateCredentialRequest {
                        id: credential.id,
                        state: Some(CredentialStateEnum::Offered),
                        suspend_end_date: Clearable::DontTouch,
                        ..Default::default()
                    })
                    .await?;
            }

            // we add refresh token for mdoc
            if credential_schema.format == "MDOC" {
                interaction_data.refresh_token = Some(generate_new_token());

                interaction_data.refresh_token_expires_at = Some(now + refresh_token_expires_in);
            }
        }

        let data = serde_json::to_vec(&interaction_data)
            .map_err(|e| ServiceError::MappingError(e.to_string()))?;

        interaction.data = Some(data);

        self.interaction_repository
            .update_interaction(interaction)
            .await?;

        interaction_data.try_into().map_err(Into::into)
    }

    // TODO (Eugeniu) - this method is used as part of the OIDC BLE flow
    // as soon as ONE-2754 is finalized, we should remove this method, and move
    // all logic to the provider instead. This is a temporary solution.
    pub async fn oidc_verifier_ble_mqtt_presentation(&self, proof_id: ProofId) {
        let Ok(Some(proof)) = self
            .proof_repository
            .get_proof(
                &proof_id,
                &ProofRelations {
                    schema: Some(ProofSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        proof_inputs: Some(ProofInputSchemaRelations {
                            claim_schemas: Some(ProofSchemaClaimRelations::default()),
                            credential_schema: Some(CredentialSchemaRelations {
                                claim_schemas: Some(ClaimSchemaRelations::default()),
                                ..Default::default()
                            }),
                        }),
                    }),
                    interaction: Some(InteractionRelations::default()),
                    ..Default::default()
                },
            )
            .await
        else {
            tracing::error!(%proof_id, "Missing proof");
            return;
        };

        let request_data_fn = || {
            let interaction_data = proof
                .interaction
                .as_ref()
                .and_then(|interaction| interaction.data.as_ref())
                .context("Missing interaction data")?;

            if proof.transport == TransportType::Ble.as_ref() {
                let interaction_data =
                    serde_json::from_slice::<BLEOpenID4VPInteractionData>(interaction_data)
                        .context("BLE interaction data deserialization")?;

                let response = interaction_data
                    .presentation_submission
                    .context("BLE interaction missing presentation_submission")?;

                let state = Uuid::from_str(&response.presentation_submission.definition_id)?;

                let request_data = RequestData {
                    presentation_submission: response.presentation_submission,
                    vp_token: response.vp_token,
                    state,
                    mdoc_generated_nonce: interaction_data.identity_request_nonce,
                    encryption_key: None,
                };

                anyhow::Ok(request_data)
            } else {
                let interaction_data =
                    serde_json::from_slice::<MQTTOpenID4VPInteractionDataVerifier>(
                        interaction_data,
                    )
                    .context("MQTT interaction data deserialization")?;

                let response = interaction_data.presentation_submission;
                let state = Uuid::from_str(&response.presentation_submission.definition_id)?;

                let request_data = RequestData {
                    presentation_submission: response.presentation_submission,
                    vp_token: response.vp_token,
                    state,
                    mdoc_generated_nonce: Some(interaction_data.identity_request_nonce),
                    encryption_key: None,
                };

                anyhow::Ok(request_data)
            }
        };

        let request_data = match request_data_fn() {
            Ok(request_data) => request_data,
            Err(error) => {
                let message = format!("Failed parsing interaction data: {error}");
                tracing::info!(message);
                let error_metadata = HistoryErrorMetadata {
                    error_code: BR_0000,
                    message,
                };
                let _ = self.mark_proof_as_failed(&proof.id, error_metadata).await;
                return;
            }
        };

        if let Err(error) = self
            .oidc_verifier_verify_submission(proof, request_data)
            .await
        {
            tracing::error!(%error, "Proof submission failed");
        }
    }

    pub async fn oidc_verifier_direct_post(
        &self,
        request: OpenID4VPDirectPostRequestDTO,
    ) -> Result<OpenID4VPDirectPostResponseDTO, ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let unpacked_request = self.unpack_direct_post_request(request).await?;
        let interaction_id = unpacked_request.state;

        let proof = self
            .proof_repository
            .get_proof_by_interaction_id(
                &interaction_id,
                &ProofRelations {
                    schema: Some(ProofSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        proof_inputs: Some(ProofInputSchemaRelations {
                            claim_schemas: Some(ProofSchemaClaimRelations::default()),
                            credential_schema: Some(CredentialSchemaRelations {
                                claim_schemas: Some(ClaimSchemaRelations::default()),
                                ..Default::default()
                            }),
                        }),
                    }),
                    interaction: Some(InteractionRelations::default()),
                    verifier_key: Some(KeyRelations::default()),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(ServiceError::BusinessLogic(
                BusinessLogicError::MissingProofForInteraction(interaction_id),
            ))?;

        self.oidc_verifier_verify_submission(proof, unpacked_request)
            .await
    }

    pub async fn oidc_verifier_verify_submission(
        &self,
        proof: Proof,
        unpacked_request: RequestData,
    ) -> Result<OpenID4VPDirectPostResponseDTO, ServiceError> {
        let organisation = proof
            .schema
            .as_ref()
            .ok_or(ServiceError::OpenID4VCIError(
                OpenID4VCIError::InvalidRequest,
            ))?
            .organisation
            .as_ref()
            .ok_or(ServiceError::OpenID4VCIError(
                OpenID4VCIError::InvalidRequest,
            ))?;

        let interaction = proof
            .interaction
            .as_ref()
            .ok_or(ServiceError::OpenID4VCIError(
                OpenID4VCIError::InvalidRequest,
            ))?;

        let interaction_data = interaction
            .data
            .as_ref()
            .ok_or(ServiceError::OpenID4VCIError(
                OpenID4VCIError::InvalidRequest,
            ))?;

        if let Some(used_key_id) = unpacked_request.encryption_key {
            let verifier_key = proof
                .verifier_key
                .as_ref()
                .ok_or(OpenID4VCIError::InvalidRequest)?;

            if used_key_id != verifier_key.id {
                tracing::info!("Proof encrypted with an incorrect key");
                return Err(ServiceError::OpenID4VCIError(
                    OpenID4VCIError::InvalidRequest,
                ));
            }
        }

        match crate::provider::exchange_protocol::openid4vc::service::oidc_verifier_direct_post(
            unpacked_request,
            proof.to_owned(),
            interaction_data,
            &self.did_method_provider,
            &self.formatter_provider,
            &self.key_algorithm_provider,
            &self.revocation_method_provider,
            map_from_oidc_format_to_core_detailed,
        )
        .await
        {
            Ok((accept_proof_result, response)) => {
                for proved_credential in accept_proof_result.proved_credentials {
                    let credential_id = proved_credential.credential.id;
                    let mdoc_mso = proved_credential.mdoc_mso.to_owned();

                    let credential = credential_from_proved(
                        proved_credential,
                        organisation,
                        &*self.did_repository,
                    )
                    .await?;

                    self.credential_repository
                        .create_credential(credential)
                        .await?;

                    if let Some(mso) = mdoc_mso {
                        let mso_cbor = encode_cbor_base64(mso).map_err(|_| {
                            ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidRequest)
                        })?;

                        self.validity_credential_repository
                            .insert(
                                Mdoc {
                                    id: Uuid::new_v4(),
                                    created_date: OffsetDateTime::now_utc(),
                                    credential: mso_cbor.into_bytes(),
                                    linked_credential_id: credential_id,
                                }
                                .into(),
                            )
                            .await?;
                    }
                }

                self.proof_repository
                    .set_proof_claims(&proof.id, convert_inner(accept_proof_result.proved_claims))
                    .await?;

                self.proof_repository
                    .update_proof(
                        &proof.id,
                        UpdateProofRequest {
                            state: Some(ProofStateEnum::Accepted),
                            ..Default::default()
                        },
                        None,
                    )
                    .await?;

                Ok(response)
            }
            Err(err) => {
                let message = format!("Proof validation failed: {err}");
                tracing::info!(message);
                let error_metadata = HistoryErrorMetadata {
                    error_code: BR_0000,
                    message,
                };
                self.mark_proof_as_failed(&proof.id, error_metadata).await?;
                Err(err.into())
            }
        }
    }

    pub async fn oidc_verifier_presentation_definition(
        &self,
        id: ProofId,
    ) -> Result<OpenID4VPPresentationDefinition, ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let proof = self
            .proof_repository
            .get_proof(
                &id,
                &ProofRelations {
                    interaction: Some(InteractionRelations::default()),
                    schema: Some(ProofSchemaRelations {
                        proof_inputs: Some(ProofInputSchemaRelations {
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(ServiceError::EntityNotFound(EntityNotFoundError::Proof(id)))?;

        validate_exchange_type(ExchangeType::OpenId4Vc, &self.config, &proof.exchange)?;
        throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Pending)?;

        let interaction = proof
            .interaction
            .as_ref()
            .ok_or(ServiceError::OpenID4VCIError(
                OpenID4VCIError::InvalidRequest,
            ))?;

        let interaction_data = parse_interaction_content(interaction.data.as_ref())?;

        crate::provider::exchange_protocol::openid4vc::service::oidc_verifier_presentation_definition(&proof, interaction_data.presentation_definition).map_err(Into::into)
    }

    async fn mark_proof_as_failed(
        &self,
        id: &ProofId,
        error_metadata: HistoryErrorMetadata,
    ) -> Result<(), ServiceError> {
        self.proof_repository
            .update_proof(
                id,
                UpdateProofRequest {
                    state: Some(ProofStateEnum::Error),
                    ..Default::default()
                },
                Some(error_metadata),
            )
            .await
            .map_err(ServiceError::from)
    }

    async fn unpack_direct_post_request(
        &self,
        request: OpenID4VPDirectPostRequestDTO,
    ) -> Result<RequestData, ServiceError> {
        match request {
            OpenID4VPDirectPostRequestDTO {
                presentation_submission: Some(presentation_submission),
                vp_token: Some(vp_token),
                state: Some(state),
                response: None,
            } => Ok(RequestData {
                presentation_submission,
                vp_token,
                state,
                mdoc_generated_nonce: None,
                encryption_key: None,
            }),
            OpenID4VPDirectPostRequestDTO {
                response: Some(jwe),
                ..
            } => {
                let jwe_header = extract_jwe_header(&jwe).map_err(|err| {
                    ServiceError::Other(format!("Failed parsing JWE header: {err}"))
                })?;

                let key_id = KeyId::from_str(&jwe_header.key_id).map_err(|err| {
                    ServiceError::ValidationError(format!("JWE key_id value invalid format: {err}"))
                })?;

                // KeyId can't be verified here since we don't know related proof yet.
                let key = self
                    .key_repository
                    .get_key(&key_id, &KeyRelations::default())
                    .await?
                    .ok_or_else(|| {
                        ServiceError::ValidationError("Invalid JWE key_id".to_string())
                    })?;

                let key_storage = self
                    .key_provider
                    .get_key_storage(&key.storage_type)
                    .ok_or_else(|| MissingProviderError::KeyStorage(key.storage_type.clone()))?;

                let key = key_storage
                    .key_handle(&key)
                    .map_err(|e| ServiceError::KeyStorageError(KeyStorageError::SignerError(e)))?
                    .private_key_as_jwk()?;

                let payload = decrypt_jwe_payload(&jwe, key).map_err(|err| {
                    ServiceError::Other(format!("Failed decrypting JWE payload: {err}"))
                })?;

                let payload = JwePayload::try_from_json_base64_decode(&payload).map_err(|err| {
                    ServiceError::Other(format!("Failed deserializing JWE payload: {err}"))
                })?;

                Ok(RequestData {
                    presentation_submission: payload.presentation_submission,
                    vp_token: payload.vp_token,
                    state: payload.state.parse()?,
                    mdoc_generated_nonce: Some(jwe_header.agreement_partyuinfo),
                    encryption_key: Some(key_id),
                })
            }
            _ => Err(ServiceError::OpenID4VCIError(
                OpenID4VCIError::InvalidRequest,
            )),
        }
    }
}

fn get_url(base_url: Option<String>) -> Result<String, ServiceError> {
    base_url.ok_or(ServiceError::Other("Missing base_url".to_owned()))
}

pub fn credentials_format(
    wallet_storage_type: Option<WalletStorageTypeEnum>,
    claims: &[Claim],
) -> Result<ExtendedSubjectDTO, OpenID4VCError> {
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

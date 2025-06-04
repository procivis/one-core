use std::str::FromStr;

use itertools::Itertools;
use one_crypto::jwe::{decrypt_jwe_payload, extract_jwe_header};
use one_dto_mapper::convert_inner;
use shared_types::{KeyId, ProofId};
use time::OffsetDateTime;
use tracing::warn;
use uuid::Uuid;

use super::OID4VPDraft25Service;
use super::mapper::credential_from_proved;
use super::proof_request::{
    generate_authorization_request_client_id_scheme_did,
    generate_authorization_request_client_id_scheme_redirect_uri,
    generate_authorization_request_client_id_scheme_verifier_attestation,
    generate_authorization_request_client_id_scheme_x509_san_dns,
};
use crate::common_mapper::{
    DidRole, encode_cbor_base64, get_encryption_key_jwk_from_proof,
    get_or_create_did_and_identifier,
};
use crate::common_validator::throw_if_latest_proof_state_not_eq;
use crate::config::core_config::VerificationProtocolType;
use crate::model::certificate::CertificateRelations;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential_schema::CredentialSchemaRelations;
use crate::model::did::DidRelations;
use crate::model::history::HistoryErrorMetadata;
use crate::model::identifier::IdentifierRelations;
use crate::model::interaction::InteractionRelations;
use crate::model::key::KeyRelations;
use crate::model::organisation::OrganisationRelations;
use crate::model::proof::{Proof, ProofRelations, ProofStateEnum, UpdateProofRequest};
use crate::model::proof_schema::{
    ProofInputSchemaRelations, ProofSchemaClaimRelations, ProofSchemaRelations,
};
use crate::model::validity_credential::Mdoc;
use crate::provider::key_storage::error::KeyStorageError;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::error::OpenID4VCError;
use crate::provider::verification_protocol::openid4vp::mapper::create_open_id_for_vp_formats;
use crate::provider::verification_protocol::openid4vp::model::{
    ClientIdScheme, JwePayload, OpenID4VPClientMetadata, OpenID4VPDirectPostRequestDTO,
    OpenID4VPDirectPostResponseDTO, OpenID4VPPresentationDefinition,
    OpenID4VPVerifierInteractionContent, SubmissionRequestData,
};
use crate::provider::verification_protocol::openid4vp::service::{
    create_open_id_for_vp_client_metadata, oid4vp_verifier_process_submission,
};
use crate::service::error::ErrorCode::BR_0000;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError,
};
use crate::service::oid4vp_draft25::mapper::parse_interaction_content;
use crate::service::oid4vp_draft25::validator::validate_config_entity_presence;
use crate::service::ssi_validator::validate_verification_protocol_type;

impl OID4VPDraft25Service {
    pub async fn get_client_request(&self, id: ProofId) -> Result<String, ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let proof = self
            .proof_repository
            .get_proof(
                &id,
                &ProofRelations {
                    interaction: Some(Default::default()),
                    verifier_identifier: Some(IdentifierRelations {
                        did: Some(DidRelations {
                            keys: Some(KeyRelations::default()),
                            ..Default::default()
                        }),
                        certificates: Some(CertificateRelations {
                            key: Some(KeyRelations::default()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    verifier_key: Some(Default::default()),
                    verifier_certificate: Some(Default::default()),
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
        validate_verification_protocol_type(
            &[VerificationProtocolType::OpenId4VpDraft25],
            &self.config,
            &proof.exchange,
        )?;

        let interaction = proof
            .interaction
            .as_ref()
            .ok_or(VerificationProtocolError::Failed(
                "missing proof interaction".to_string(),
            ))?;

        let interaction_data: OpenID4VPVerifierInteractionContent =
            parse_interaction_content(interaction.data.as_ref())
                .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        let client_id_scheme =
            interaction_data
                .client_id_scheme
                .ok_or(VerificationProtocolError::Failed(
                    "missing client_id_scheme".to_string(),
                ))?;
        Ok(match client_id_scheme {
            ClientIdScheme::RedirectUri => {
                generate_authorization_request_client_id_scheme_redirect_uri(
                    &proof,
                    interaction_data,
                    &interaction.id,
                    &*self.key_algorithm_provider,
                    &*self.key_provider,
                )
                .await?
            }
            ClientIdScheme::VerifierAttestation => {
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
            ClientIdScheme::Did => {
                generate_authorization_request_client_id_scheme_did(
                    &proof,
                    interaction_data,
                    &interaction.id,
                    &self.key_algorithm_provider,
                    &*self.key_provider,
                    &*self.did_method_provider,
                )
                .await?
            }
            ClientIdScheme::X509SanDns => {
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

    pub async fn get_client_metadata(
        &self,
        id: ProofId,
    ) -> Result<OpenID4VPClientMetadata, ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let proof = self
            .proof_repository
            .get_proof(
                &id,
                &ProofRelations {
                    verifier_identifier: Some(IdentifierRelations {
                        did: Some(DidRelations {
                            keys: Some(KeyRelations::default()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    verifier_key: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(ServiceError::EntityNotFound(EntityNotFoundError::Proof(id)))?;

        throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Pending)?;
        validate_verification_protocol_type(
            &[VerificationProtocolType::OpenId4VpDraft25],
            &self.config,
            &proof.exchange,
        )?;

        let formats = create_open_id_for_vp_formats();
        let jwk = get_encryption_key_jwk_from_proof(
            &proof,
            &*self.key_algorithm_provider,
            &*self.key_provider,
        )?;

        Ok(create_open_id_for_vp_client_metadata(jwk, formats))
    }

    pub async fn direct_post(
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

        self.verify_submission(proof, unpacked_request).await
    }

    async fn verify_submission(
        &self,
        proof: Proof,
        unpacked_request: SubmissionRequestData,
    ) -> Result<OpenID4VPDirectPostResponseDTO, ServiceError> {
        let organisation = proof
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "missing proof schema".to_string(),
            ))?
            .organisation
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "missing organisation".to_string(),
            ))?;

        let interaction = proof
            .interaction
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "missing interaction".to_string(),
            ))?;

        let interaction_data: OpenID4VPVerifierInteractionContent =
            parse_interaction_content(interaction.data.as_ref())
                .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        if let Some(used_key_id) = unpacked_request.encryption_key {
            let encryption_key_id =
                interaction_data
                    .encryption_key_id
                    .as_ref()
                    .ok_or(ServiceError::MappingError(
                        "missing encryption key".to_string(),
                    ))?;

            if used_key_id != *encryption_key_id {
                tracing::info!("Proof encrypted with an incorrect key");
                return Err(OpenID4VCError::ValidationError(
                    "Proof encrypted with an incorrect key".to_string(),
                )
                .into());
            }
        }

        match oid4vp_verifier_process_submission(
            unpacked_request,
            proof.to_owned(),
            interaction_data,
            &self.did_method_provider,
            &self.formatter_provider,
            &self.key_algorithm_provider,
            &self.revocation_method_provider,
            &self.certificate_validator,
            &self.config,
        )
        .await
        {
            Ok((accept_proof_result, response)) => {
                // store holder did on proof if it is not ambiguous
                let holder_did_value = accept_proof_result
                    .proved_credentials
                    .iter()
                    .map(|cred| &cred.holder_did_value)
                    .all_equal_value()
                    .ok();
                let holder_identifier_id = if let Some(holder_did_value) = holder_did_value {
                    let (_, identifer) = get_or_create_did_and_identifier(
                        &*self.did_method_provider,
                        &*self.did_repository,
                        &*self.identifier_repository,
                        &Some(organisation.to_owned()),
                        holder_did_value,
                        DidRole::Holder,
                    )
                    .await?;
                    Some(identifer.id)
                } else {
                    None
                };

                for proved_credential in accept_proof_result.proved_credentials {
                    let credential_id = proved_credential.credential.id;
                    let mdoc_mso = proved_credential.mdoc_mso.to_owned();

                    let credential = credential_from_proved(
                        proved_credential,
                        organisation,
                        &*self.did_repository,
                        &*self.certificate_repository,
                        &*self.identifier_repository,
                        &*self.certificate_validator,
                        &*self.did_method_provider,
                    )
                    .await?;

                    self.credential_repository
                        .create_credential(credential)
                        .await?;

                    if let Some(mso) = mdoc_mso {
                        let mso_cbor = encode_cbor_base64(mso)
                            .map_err(|e| OpenID4VCError::Other(e.to_string()))?;

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
                            holder_identifier_id,
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
                self.mark_proof_as_failed(&proof.id, error_metadata).await;
                Err(err.into())
            }
        }
    }

    pub async fn presentation_definition(
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

        validate_verification_protocol_type(
            &[VerificationProtocolType::OpenId4VpDraft25],
            &self.config,
            &proof.exchange,
        )?;
        throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Pending)?;

        let interaction = proof
            .interaction
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "missing interaction".to_string(),
            ))?;

        let interaction_data = parse_interaction_content(interaction.data.as_ref())?;

        crate::provider::verification_protocol::openid4vp::service::oidc_verifier_presentation_definition(&proof, interaction_data.presentation_definition).map_err(Into::into)
    }

    async fn mark_proof_as_failed(&self, id: &ProofId, error_metadata: HistoryErrorMetadata) {
        let result = self
            .proof_repository
            .update_proof(
                id,
                UpdateProofRequest {
                    state: Some(ProofStateEnum::Error),
                    ..Default::default()
                },
                Some(error_metadata),
            )
            .await;
        if let Err(err) = result {
            warn!("Failed to set proof state to 'ERROR': {err}");
        }
    }

    async fn unpack_direct_post_request(
        &self,
        request: OpenID4VPDirectPostRequestDTO,
    ) -> Result<SubmissionRequestData, ServiceError> {
        match request {
            OpenID4VPDirectPostRequestDTO {
                presentation_submission: Some(presentation_submission),
                vp_token: Some(vp_token),
                state: Some(state),
                response: None,
            } => Ok(SubmissionRequestData {
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
                    .map_err(|e| ServiceError::KeyStorageError(KeyStorageError::SignerError(e)))?;

                let key = key
                    .key_agreement()
                    .and_then(|k| k.private())
                    .ok_or_else(|| {
                        ServiceError::ValidationError("Unsupported JWE key".to_string())
                    })?;

                let payload = decrypt_jwe_payload(&jwe, key.as_ref())
                    .await
                    .map_err(|err| {
                        ServiceError::Other(format!("Failed decrypting JWE payload: {err}"))
                    })?;

                let payload = JwePayload::try_from_json_base64_decode(&payload).map_err(|err| {
                    ServiceError::Other(format!("Failed deserializing JWE payload: {err}"))
                })?;

                Ok(SubmissionRequestData {
                    presentation_submission: payload.presentation_submission,
                    vp_token: payload.vp_token,
                    state: payload
                        .state
                        .ok_or(ServiceError::ValidationError(
                            "missing state parameter".to_string(),
                        ))?
                        .parse()?,
                    mdoc_generated_nonce: Some(jwe_header.agreement_partyuinfo),
                    encryption_key: Some(key_id),
                })
            }
            _ => Err(ServiceError::OpenID4VCError(OpenID4VCError::InvalidRequest)),
        }
    }
}

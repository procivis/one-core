use std::str::FromStr;

use one_crypto::jwe::{decrypt_jwe_payload, extract_jwe_header};
use shared_types::{BlobId, KeyId, ProofId};
use standardized_types::openid4vp::ClientMetadata;
use tracing::warn;

use super::OID4VPFinal1_0Service;
use super::error::OID4VPFinal1_0ServiceError;
use super::mapper::parse_interaction_content;
use super::proof_request::{
    generate_authorization_request_params_final1_0, select_key_agreement_key_from_proof,
};
use crate::config::core_config::VerificationProtocolType;
use crate::error::ContextWithErrorCode;
use crate::error::ErrorCode::BR_0000;
use crate::model::blob::{Blob, BlobType};
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
use crate::provider::blob_storage_provider::BlobStorageType;
use crate::provider::verification_protocol::openid4vp::error::OpenID4VCError;
use crate::provider::verification_protocol::openid4vp::final1_0::mappers::{
    create_open_id_for_vp_client_metadata_final1_0, decode_client_id_with_scheme,
};
use crate::provider::verification_protocol::openid4vp::mapper::{
    format_authorization_request_client_id_scheme_did,
    format_authorization_request_client_id_scheme_redirect_uri,
    format_authorization_request_client_id_scheme_verifier_attestation,
    format_authorization_request_client_id_scheme_x509,
};
use crate::provider::verification_protocol::openid4vp::model::{
    ClientIdScheme, JwePayload, OpenID4VPDirectPostRequestDTO, OpenID4VPDirectPostResponseDTO,
    OpenID4VPVerifierInteractionContent, ResponseSubmission, SubmissionRequestData,
    VpSubmissionData,
};
use crate::service::error::MissingProviderError;
use crate::service::ssi_validator::validate_verification_protocol_type;
use crate::util::openid4vp::persist_accepted_proof;
use crate::validator::{throw_if_proof_state_not_eq, validate_verification_protocol_config_exists};

impl OID4VPFinal1_0Service {
    pub async fn get_client_request(
        &self,
        id: ProofId,
    ) -> Result<String, OID4VPFinal1_0ServiceError> {
        validate_verification_protocol_config_exists(
            &self.config,
            &[VerificationProtocolType::OpenId4VpFinal1_0],
        )
        .error_while("checking config")?;

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
                None,
            )
            .await
            .error_while("getting proof")?
            .ok_or(OID4VPFinal1_0ServiceError::MissingProof(id))?;

        throw_if_proof_state_not_eq(&proof, ProofStateEnum::Pending)
            .error_while("checking proof state")?;
        validate_verification_protocol_type(
            &[VerificationProtocolType::OpenId4VpFinal1_0],
            &self.config,
            &proof.protocol,
        )
        .error_while("validating protocol type")?;

        let interaction =
            proof
                .interaction
                .as_ref()
                .ok_or(OID4VPFinal1_0ServiceError::MappingError(
                    "missing proof interaction".to_string(),
                ))?;

        let OpenID4VPVerifierInteractionContent {
            nonce,
            dcql_query: Some(dcql_query),
            client_id,
            response_uri: Some(response_uri),
            client_id_scheme: Some(client_id_scheme),
            ..
        } = parse_interaction_content(interaction.data.as_ref())
            .error_while("parsing interaction data")?
        else {
            return Err(OID4VPFinal1_0ServiceError::MappingError(
                "missing interaction data".to_string(),
            ));
        };

        let (client_id_without_prefix, _) =
            decode_client_id_with_scheme(&client_id).error_while("decoding clientId")?;

        let key_handle = select_key_agreement_key_from_proof(
            &proof,
            &*self.key_algorithm_provider,
            &self.config,
        )
        .error_while("selecting agreement key")?;

        let authorization_request = generate_authorization_request_params_final1_0(
            nonce.clone(),
            dcql_query.clone(),
            client_id.clone(),
            response_uri.clone(),
            &interaction.id,
            create_open_id_for_vp_client_metadata_final1_0(key_handle)
                .error_while("creating metadata")?,
        )
        .error_while("generating authorization request")?;

        Ok(match client_id_scheme {
            ClientIdScheme::RedirectUri => {
                format_authorization_request_client_id_scheme_redirect_uri(authorization_request)
                    .await
                    .error_while("formatting authorization request")?
            }
            ClientIdScheme::VerifierAttestation => {
                format_authorization_request_client_id_scheme_verifier_attestation(
                    &proof,
                    &self.key_algorithm_provider,
                    &*self.key_provider,
                    client_id_without_prefix,
                    response_uri.clone(),
                    authorization_request,
                )
                .await
                .error_while("formatting authorization request")?
            }
            ClientIdScheme::Did => format_authorization_request_client_id_scheme_did(
                &proof,
                &self.key_algorithm_provider,
                &*self.key_provider,
                authorization_request,
            )
            .await
            .error_while("formatting authorization request")?,
            ClientIdScheme::X509SanDns | ClientIdScheme::X509Hash => {
                format_authorization_request_client_id_scheme_x509(
                    &proof,
                    &self.key_algorithm_provider,
                    &*self.key_provider,
                    authorization_request,
                )
                .await
                .error_while("formatting authorization request")?
            }
        })
    }

    pub async fn get_client_metadata(
        &self,
        id: ProofId,
    ) -> Result<ClientMetadata, OID4VPFinal1_0ServiceError> {
        validate_verification_protocol_config_exists(
            &self.config,
            &[VerificationProtocolType::OpenId4VpFinal1_0],
        )
        .error_while("checking config")?;

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
                None,
            )
            .await
            .error_while("getting proof")?
            .ok_or(OID4VPFinal1_0ServiceError::MissingProof(id))?;

        throw_if_proof_state_not_eq(&proof, ProofStateEnum::Pending)
            .error_while("checking proof state")?;
        validate_verification_protocol_type(
            &[VerificationProtocolType::OpenId4VpFinal1_0],
            &self.config,
            &proof.protocol,
        )
        .error_while("validating protocol type")?;

        let key_handle = select_key_agreement_key_from_proof(
            &proof,
            &*self.key_algorithm_provider,
            &self.config,
        )
        .error_while("selecting agreement key")?;

        Ok(create_open_id_for_vp_client_metadata_final1_0(key_handle)
            .error_while("creating metadata")?)
    }

    pub async fn direct_post(
        &self,
        request: OpenID4VPDirectPostRequestDTO,
    ) -> Result<OpenID4VPDirectPostResponseDTO, OID4VPFinal1_0ServiceError> {
        validate_verification_protocol_config_exists(
            &self.config,
            &[VerificationProtocolType::OpenId4VpFinal1_0],
        )
        .error_while("checking config")?;

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
            .await
            .error_while("getting proof")?
            .ok_or(OID4VPFinal1_0ServiceError::MissingProofForInteraction(
                interaction_id,
            ))?;

        let proof_id = proof.id;
        let result = self.verify_submission(proof, unpacked_request).await?;
        tracing::info!("Successfully verified response for proof request {proof_id}",);
        Ok(result)
    }

    async fn verify_submission(
        &self,
        proof: Proof,
        unpacked_request: SubmissionRequestData,
    ) -> Result<OpenID4VPDirectPostResponseDTO, OID4VPFinal1_0ServiceError> {
        let organisation = proof
            .schema
            .as_ref()
            .ok_or(OID4VPFinal1_0ServiceError::MappingError(
                "missing proof schema".to_string(),
            ))?
            .organisation
            .as_ref()
            .ok_or(OID4VPFinal1_0ServiceError::MappingError(
                "missing organisation".to_string(),
            ))?;

        let interaction =
            proof
                .interaction
                .as_ref()
                .ok_or(OID4VPFinal1_0ServiceError::MappingError(
                    "missing interaction".to_string(),
                ))?;

        let interaction_data: OpenID4VPVerifierInteractionContent =
            parse_interaction_content(interaction.data.as_ref())
                .error_while("parsing interaction data")?;

        if let Some(used_key_id) = unpacked_request.encryption_key {
            let encryption_key_id = interaction_data
                .encryption_key
                .as_ref()
                .and_then(|key| key.kid())
                .ok_or(OID4VPFinal1_0ServiceError::MappingError(
                    "missing encryption key".to_string(),
                ))?;

            if used_key_id.to_string() != encryption_key_id {
                tracing::info!("Proof encrypted with an incorrect key");
                return Err(OpenID4VCError::ValidationError(
                    "Proof encrypted with an incorrect key".to_string(),
                )
                .into());
            }
        }

        let blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)
            .await
            .ok_or_else(|| MissingProviderError::BlobStorage(BlobStorageType::Db.to_string()))
            .error_while("getting blob storage")?;

        let blob_value = serde_json::to_string(&unpacked_request.submission_data).map_err(|e| {
            OID4VPFinal1_0ServiceError::MappingError(format!(
                "failed to serialize proof blob data: {e}"
            ))
        })?;

        let blob = Blob::new(blob_value, BlobType::Proof);
        let proof_blob_id = blob.id;
        blob_storage
            .create(blob)
            .await
            .error_while("creating proof blob")?;

        match self
            .proof_validator
            .validate_submission(
                unpacked_request.clone(),
                proof.to_owned(),
                interaction_data,
                VerificationProtocolType::OpenId4VpFinal1_0,
            )
            .await
        {
            Ok((accept_proof_result, response)) => {
                persist_accepted_proof(
                    &proof,
                    accept_proof_result,
                    organisation,
                    proof_blob_id,
                    &*self.proof_repository,
                    &*self.credential_repository,
                    &*self.validity_credential_repository,
                    &*self.transaction_manager,
                    &*self.identifier_creator,
                )
                .await
                .error_while("persisting proof")?;
                Ok(response)
            }
            Err(err) => {
                let message = format!("Proof validation failed: {err}");
                tracing::info!(message);
                let error_metadata = HistoryErrorMetadata {
                    error_code: BR_0000,
                    message,
                };
                self.mark_proof_as_failed(&proof.id, proof_blob_id, error_metadata)
                    .await;
                Err(err.into())
            }
        }
    }

    async fn mark_proof_as_failed(
        &self,
        id: &ProofId,
        proof_blob_id: BlobId,
        error_metadata: HistoryErrorMetadata,
    ) {
        let result = self
            .proof_repository
            .update_proof(
                id,
                UpdateProofRequest {
                    state: Some(ProofStateEnum::Error),
                    proof_blob_id: Some(Some(proof_blob_id)),
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
    ) -> Result<SubmissionRequestData, OID4VPFinal1_0ServiceError> {
        match request {
            OpenID4VPDirectPostRequestDTO {
                submission_data: VpSubmissionData::Dcql(_) | VpSubmissionData::Pex(_),
                state: Some(state),
            } => Ok(SubmissionRequestData {
                submission_data: request.submission_data,
                state,
                mdoc_generated_nonce: None,
                encryption_key: None,
            }),
            OpenID4VPDirectPostRequestDTO {
                submission_data:
                    VpSubmissionData::EncryptedResponse(ResponseSubmission { response: jwe }),
                ..
            } => {
                let jwe_header = extract_jwe_header(&jwe).map_err(|err| {
                    OID4VPFinal1_0ServiceError::ValidationError(format!(
                        "Failed parsing JWE header: {err}"
                    ))
                })?;

                let key_id = KeyId::from_str(&jwe_header.key_id).map_err(|err| {
                    OID4VPFinal1_0ServiceError::ValidationError(format!(
                        "JWE key_id value invalid format: {err}"
                    ))
                })?;

                // KeyId can't be verified here since we don't know related proof yet.
                let key = self
                    .key_repository
                    .get_key(&key_id, &KeyRelations::default())
                    .await
                    .error_while("getting key")?
                    .ok_or_else(|| {
                        OID4VPFinal1_0ServiceError::ValidationError(
                            "Invalid JWE key_id".to_string(),
                        )
                    })?;

                let key_storage = self
                    .key_provider
                    .get_key_storage(&key.storage_type)
                    .ok_or_else(|| MissingProviderError::KeyStorage(key.storage_type.clone()))
                    .error_while("getting key storage")?;

                let key = key_storage
                    .key_handle(&key)
                    .error_while("getting key handle")?;

                let key = key
                    .key_agreement()
                    .and_then(|k| k.private())
                    .ok_or_else(|| {
                        OID4VPFinal1_0ServiceError::ValidationError(
                            "Unsupported JWE key".to_string(),
                        )
                    })?;

                let payload = decrypt_jwe_payload(&jwe, key.as_ref())
                    .await
                    .map_err(|err| {
                        OID4VPFinal1_0ServiceError::ValidationError(format!(
                            "Failed decrypting JWE payload: {err}"
                        ))
                    })?;

                let payload = JwePayload::try_from_json_base64_decode(&payload).map_err(|err| {
                    OID4VPFinal1_0ServiceError::ValidationError(format!(
                        "Failed deserializing JWE payload: {err}"
                    ))
                })?;

                Ok(SubmissionRequestData {
                    submission_data: payload.submission_data,
                    state: payload
                        .state
                        .ok_or(OID4VPFinal1_0ServiceError::ValidationError(
                            "missing state parameter".to_string(),
                        ))?
                        .parse()
                        .map_err(|err| {
                            OID4VPFinal1_0ServiceError::ValidationError(format!(
                                "Invalid state parameter: {err}"
                            ))
                        })?,
                    mdoc_generated_nonce: jwe_header.agreement_partyuinfo,
                    encryption_key: Some(key_id),
                })
            }
            _ => Err(OpenID4VCError::InvalidRequest.into()),
        }
    }
}

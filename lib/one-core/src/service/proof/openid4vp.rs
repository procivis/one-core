use std::borrow::Cow;

use shared_types::{BlobId, EcosystemId, ProofId};
use standardized_types::openid4vp::DirectPostResponse;

use super::ProofService;
use super::error::ProofServiceError;
use crate::config::core_config::BlobStorageType;
use crate::error::{ContextWithErrorCode, ErrorCode};
use crate::model::blob::{Blob, BlobType};
use crate::model::history::HistoryErrorMetadata;
use crate::model::proof::{Proof, ProofStateEnum, UpdateProofRequest};
use crate::model::relation::OptionalRelatedExt;
use crate::proto::openid4vp_proof_validator::ValidatedProofResult;
use crate::provider::ecosystem::model::ProtocolArtifact;
use crate::provider::verification_protocol::openid4vp::error::OpenID4VCError;
use crate::provider::verification_protocol::openid4vp::model::{
    OpenID4VPVerifierInteractionContent, SubmissionRequestData, VpSubmissionData,
};
use crate::service::oid4vp_final1_0::service::{DecryptedResponse, decrypt_response};
use crate::util::openid4vp::persist_accepted_proof;

impl ProofService {
    pub(super) async fn handle_openid4vp_dc_api_response(
        &self,
        proof: Proof,
        submission: VpSubmissionData,
    ) -> Result<(), ProofServiceError> {
        let interaction_id = proof
            .interaction
            .id_opt()
            .ok_or(ProofServiceError::MappingError(
                "Missing proof interaction".to_string(),
            ))?;

        let submission = match submission {
            VpSubmissionData::Unencrypted(submission) => SubmissionRequestData {
                submission,
                interaction_id,
                mdoc_generated_nonce: None,
                encryption_key: None,
            },
            VpSubmissionData::Encrypted(encrypted_response) => {
                let DecryptedResponse {
                    payload,
                    encryption_key,
                    mdoc_generated_nonce,
                } = decrypt_response(
                    encrypted_response,
                    self.key_provider.as_ref(),
                    self.key_repository.as_ref(),
                )
                .await
                .error_while("decrypting response")?;

                SubmissionRequestData {
                    submission: payload.submission_data,
                    interaction_id,
                    mdoc_generated_nonce,
                    encryption_key: Some(encryption_key.id),
                }
            }
        };

        self.verify_submission(proof, submission)
            .await
            .map_err(|error| ProofServiceError::InvalidSubmission(error.to_string()))?;

        Ok(())
    }

    pub(super) async fn verify_submission(
        &self,
        proof: Proof,
        unpacked_request: SubmissionRequestData,
    ) -> Result<DirectPostResponse, ProofServiceError> {
        let proof_schema = proof.schema.as_required_ref().await?;

        let interaction = proof.interaction.as_required_ref().await?;

        let interaction_data: OpenID4VPVerifierInteractionContent = interaction
            .data
            .as_ref()
            .ok_or(ProofServiceError::MappingError(
                "missing interaction data".to_string(),
            ))
            .and_then(|d| {
                serde_json::from_slice(d)
                    .map_err(|e| ProofServiceError::MappingError(e.to_string()))
            })?;

        if let Some(used_key_id) = unpacked_request.encryption_key {
            let verifier_key =
                proof
                    .verifier_key
                    .as_ref()
                    .ok_or(ProofServiceError::MappingError(
                        "missing verifier_key".to_string(),
                    ))?;

            if used_key_id != verifier_key.id() {
                tracing::info!("Proof encrypted with an incorrect key");
                return Err(OpenID4VCError::ValidationError(
                    "Proof encrypted with an incorrect key".to_string(),
                )
                .into());
            }
        }

        let blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)?;

        let blob_value = serde_json::to_string(&unpacked_request.submission).map_err(|e| {
            ProofServiceError::MappingError(format!("failed to serialize proof blob data: {e}"))
        })?;

        let blob = Blob::new(blob_value, BlobType::Proof);
        let proof_blob_id = blob.id;
        blob_storage
            .create(blob)
            .await
            .error_while("creating proof blob")?;

        let protocol_type = self
            .config
            .verification_protocol
            .get_type(&proof.protocol)
            .error_while("getting verification protocol type")?;

        let validation_result: Result<
            (
                ValidatedProofResult,
                Option<EcosystemId>,
                DirectPostResponse,
            ),
            ProofServiceError,
        > = async {
            let (mut proof_result, response) = self
                .proof_validator
                .validate_submission(unpacked_request, &proof, interaction_data, protocol_type)
                .await?;

            let ecosystems = {
                let artifacts = proof_result
                    .proved_credentials
                    .iter()
                    .map(|proved_credential| ProtocolArtifact::VerifierSubmission {
                        credential_id: proved_credential.common.id,
                        claims: Cow::Borrowed(&proved_credential.claims),
                        format: Cow::Borrowed(&proved_credential.format),
                        issuer_details: Cow::Borrowed(&proved_credential.issuer_details),
                        proof_id: proof.id,
                    })
                    .collect::<Vec<_>>();

                self.ecosystem_resolver
                    .resolve(interaction.id, &artifacts, None)
                    .await
                    .error_while("resolving ecosystems")?
            };

            for (proved_credential, ecosystem) in proof_result
                .proved_credentials
                .iter_mut()
                .zip(ecosystems.per_credential)
            {
                proved_credential.common.ecosystem = ecosystem;
            }

            Ok((proof_result, ecosystems.ecosystem, response))
        }
        .await;

        match validation_result {
            Ok((accept_proof_result, ecosystem, response)) => {
                persist_accepted_proof(
                    &proof,
                    accept_proof_result,
                    &proof_schema.organisation,
                    proof_blob_id,
                    Some(ecosystem),
                    &*self.proof_repository,
                    &*self.credential_repository,
                    &*self.transaction_manager,
                    &*self.identifier_creator,
                )
                .await
                .error_while("persisting accepted proof")?;

                Ok(response)
            }
            Err(err) => {
                let message = format!("Proof validation failed: {err}");
                self.mark_proof_as_failed(&proof.id, Some(proof_blob_id), message)
                    .await;
                Err(err)
            }
        }
    }

    pub(super) async fn mark_proof_as_failed(
        &self,
        id: &ProofId,
        proof_blob_id: Option<BlobId>,
        message: String,
    ) {
        tracing::info!(message);
        let error_metadata = HistoryErrorMetadata {
            error_code: ErrorCode::BR_0000,
            message,
        };

        let result = self
            .proof_repository
            .update_proof(
                id,
                UpdateProofRequest {
                    state: Some(ProofStateEnum::Error),
                    proof_blob_id: proof_blob_id.map(Some),
                    ..Default::default()
                },
                Some(error_metadata),
            )
            .await;
        if let Err(err) = result {
            tracing::warn!("Failed to set proof state to 'ERROR': {err}");
        }
    }
}

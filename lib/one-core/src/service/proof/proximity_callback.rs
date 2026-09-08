use std::borrow::Cow;
use std::str::FromStr;

use anyhow::Context;
use futures::FutureExt;
use futures::future::BoxFuture;
use shared_types::{BlobId, EcosystemId, ProofId};
use standardized_types::openid4vp::DirectPostResponse;
use tracing::warn;
use uuid::Uuid;

use super::ProofService;
use super::error::ProofServiceError;
use crate::config::core_config::{BlobStorageType, TransportType, VerificationProtocolType};
use crate::error::ContextWithErrorCode;
use crate::error::ErrorCode::BR_0000;
use crate::model::blob::{Blob, BlobType};
use crate::model::history::HistoryErrorMetadata;
use crate::model::proof::{Proof, ProofStateEnum, UpdateProofRequest};
use crate::proto::openid4vp_proof_validator::ValidatedProofResult;
use crate::provider::ecosystem::model::ProtocolArtifact;
use crate::provider::verification_protocol::openid4vp::error::OpenID4VCError;
use crate::provider::verification_protocol::openid4vp::model::{
    OpenID4VPVerifierInteractionContent, SubmissionRequestData, VpSubmissionData,
};
use crate::provider::verification_protocol::openid4vp::proximity_draft00::ble::model::{
    BLEOpenID4VPInteractionDataVerifier, BLEVerifierProtocolData,
};
use crate::provider::verification_protocol::openid4vp::proximity_draft00::mqtt::model::{
    MQTTOpenID4VPInteractionDataVerifier, MQTTVerifierProtocolData,
};
use crate::util::openid4vp::persist_accepted_proof;
use crate::validator::ecosystem::{SelectionRole, resolve_credential_ecosystems};

impl ProofService {
    // TODO: This method is used as part of the OID4VP BLE/MQTT flow
    // This is a workaround solution for asynchronous background handling of proof submission.
    pub(super) fn get_on_submission_ble_mqtt_callback(
        &self,
        proof_id: ProofId,
    ) -> BoxFuture<'static, ()> {
        let service = self.clone();
        async move {
            service.ble_mqtt_presentation(proof_id).await;
        }
        .boxed()
    }

    async fn ble_mqtt_presentation(&self, proof_id: ProofId) {
        let Ok(proof) = self.proof_repository.get_proof(&proof_id, None).await else {
            tracing::error!(%proof_id, "Missing proof");
            return;
        };

        let request_data_fn = async || {
            let interaction = proof
                .interaction
                .as_ref()
                .context("Missing interaction")?
                .as_ref()
                .await?;
            let interaction_data = interaction
                .data
                .as_ref()
                .context("Missing interaction data")?;

            if proof.transport == TransportType::Ble.as_ref() {
                let interaction_data =
                    serde_json::from_slice::<BLEOpenID4VPInteractionDataVerifier>(interaction_data)
                        .context("BLE interaction data deserialization")?;

                let (state, submission_data) = match interaction_data.protocol_data {
                    BLEVerifierProtocolData::V1 {
                        submission: Some(submission),
                        ..
                    } => (
                        Uuid::from_str(&submission.presentation_submission.definition_id)?.into(),
                        VpSubmissionData::Pex(submission),
                    ),
                    BLEVerifierProtocolData::V2 {
                        submission: Some(submission),
                        ..
                    } => (Uuid::new_v4().into(), VpSubmissionData::Dcql(submission)),
                    _ => {
                        return Err(anyhow::anyhow!(
                            "BLE interaction missing presentation_submission"
                        ));
                    }
                };

                let request_data = SubmissionRequestData {
                    submission_data,
                    state,
                    mdoc_generated_nonce: interaction_data.mdoc_generated_nonce,
                    encryption_key: None,
                };

                anyhow::Ok(request_data)
            } else {
                let interaction_data =
                    serde_json::from_slice::<MQTTOpenID4VPInteractionDataVerifier>(
                        interaction_data,
                    )
                    .context("MQTT interaction data deserialization")?;

                let (state, submission_data) = match interaction_data.protocol_data {
                    MQTTVerifierProtocolData::V1 { submission, .. } => (
                        Uuid::from_str(&submission.presentation_submission.definition_id)?.into(),
                        VpSubmissionData::Pex(submission),
                    ),
                    MQTTVerifierProtocolData::V2 { submission, .. } => {
                        (Uuid::new_v4().into(), VpSubmissionData::Dcql(submission))
                    }
                };

                let request_data = SubmissionRequestData {
                    submission_data,
                    state,
                    mdoc_generated_nonce: interaction_data.mdoc_generated_nonce,
                    encryption_key: None,
                };

                anyhow::Ok(request_data)
            }
        };

        let request_data = match request_data_fn().await {
            Ok(request_data) => request_data,
            Err(error) => {
                let message = format!("Failed parsing interaction data: {error}");
                self.mark_proof_as_failed(&proof.id, None, message).await;
                return;
            }
        };

        if let Err(error) = self.verify_submission(proof, request_data).await {
            tracing::error!(%error, "Proof submission failed");
        }
    }

    async fn verify_submission(
        &self,
        proof: Proof,
        unpacked_request: SubmissionRequestData,
    ) -> Result<DirectPostResponse, ProofServiceError> {
        let proof_schema = proof
            .schema
            .as_ref()
            .ok_or(ProofServiceError::MappingError(
                "missing proof schema".to_string(),
            ))?
            .as_ref()
            .await?;
        let organisation = proof_schema.organisation.as_ref().await?;

        let interaction = proof
            .interaction
            .as_ref()
            .ok_or(ProofServiceError::MappingError(
                "missing interaction".to_string(),
            ))?
            .as_ref()
            .await?;

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

        let blob_value = serde_json::to_string(&unpacked_request.submission_data).map_err(|e| {
            ProofServiceError::MappingError(format!("failed to serialize proof blob data: {e}"))
        })?;

        let blob = Blob::new(blob_value, BlobType::Proof);
        let proof_blob_id = blob.id;
        blob_storage
            .create(blob)
            .await
            .error_while("creating proof blob")?;

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
                .validate_submission(
                    unpacked_request,
                    proof.to_owned(),
                    interaction_data,
                    VerificationProtocolType::OpenId4VpProximityDraft00,
                )
                .await?;

            let ecosystems = {
                let artifacts = proof_result
                    .proved_credentials
                    .iter()
                    .map(|proved_credential| ProtocolArtifact::VerifierSubmission {
                        credential: Cow::Borrowed(&proved_credential.credential),
                        issuer_details: Cow::Borrowed(&proved_credential.issuer_details),
                    })
                    .collect::<Vec<_>>();

                resolve_credential_ecosystems(
                    interaction.id,
                    &artifacts,
                    self.interaction_repository.as_ref(),
                    self.ecosystem_provider.as_ref(),
                    SelectionRole::Verifier,
                )
                .await
                .error_while("resolving ecosystems")?
            };

            for (proved_credential, ecosystem) in proof_result
                .proved_credentials
                .iter_mut()
                .zip(ecosystems.per_credential)
            {
                proved_credential.credential.ecosystem = ecosystem;
            }

            Ok((proof_result, ecosystems.committed, response))
        }
        .await;

        match validation_result {
            Ok((accept_proof_result, ecosystem, response)) => {
                persist_accepted_proof(
                    &proof,
                    accept_proof_result,
                    &organisation,
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

    async fn mark_proof_as_failed(
        &self,
        id: &ProofId,
        proof_blob_id: Option<BlobId>,
        message: String,
    ) {
        tracing::info!(message);
        let error_metadata = HistoryErrorMetadata {
            error_code: BR_0000,
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
            warn!("Failed to set proof state to 'ERROR': {err}");
        }
    }
}

use anyhow::Context;
use futures::FutureExt;
use futures::future::BoxFuture;
use shared_types::{InteractionId, ProofId};

use super::ProofService;
use crate::config::core_config::TransportType;
use crate::provider::verification_protocol::openid4vp::model::SubmissionRequestData;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::ble::model::{
    BLEOpenID4VPInteractionDataVerifier, BLEVerifierProtocolData,
};
use crate::provider::verification_protocol::openid4vp::proximity_draft00::mqtt::model::{
    MQTTOpenID4VPInteractionDataVerifier, MQTTVerifierProtocolData,
};

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

                let (interaction_id, submission) = match interaction_data.protocol_data {
                    BLEVerifierProtocolData::V2 {
                        submission: Some(submission),
                        ..
                    } => (InteractionId::new(), submission),
                    _ => {
                        return Err(anyhow::anyhow!(
                            "BLE interaction missing presentation_submission"
                        ));
                    }
                };

                let request_data = SubmissionRequestData {
                    submission,
                    interaction_id,
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

                let (interaction_id, submission) = match interaction_data.protocol_data {
                    MQTTVerifierProtocolData::V2 { submission, .. } => {
                        (InteractionId::new(), submission)
                    }
                };

                let request_data = SubmissionRequestData {
                    submission,
                    interaction_id,
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
}

use std::sync::Arc;

use anyhow::Context;
use time::{Duration, OffsetDateTime};
use tokio::sync::Notify;

use crate::model::interaction::{Interaction, InteractionId};
use crate::model::proof::{Proof, ProofState, ProofStateEnum, UpdateProofRequest};
use crate::provider::exchange_protocol::error::ExchangeProtocolError;
use crate::provider::exchange_protocol::openid4vc::key_agreement_key::KeyAgreementKey;
use crate::provider::exchange_protocol::openid4vc::mapper::parse_identity_request;
use crate::provider::exchange_protocol::openid4vc::model::{
    MQTTOpenID4VPInteractionDataVerifier, MQTTOpenId4VpResponse, MqttOpenId4VpRequest,
};
use crate::provider::exchange_protocol::openid4vc::peer_encryption::PeerEncryption;
use crate::provider::mqtt_client::MqttTopic;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;

pub(super) struct Topics {
    pub(super) identify: Box<dyn MqttTopic>,
    pub(super) presentation_definition: Box<dyn MqttTopic>,
    pub(super) accept: Box<dyn MqttTopic>,
    pub(super) reject: Box<dyn MqttTopic>,
}

#[tracing::instrument(level = "debug", skip_all, err(Debug))]
#[allow(clippy::too_many_arguments)]
pub(super) async fn mqtt_verifier_flow(
    mut topics: Topics,
    keypair: KeyAgreementKey,
    proof: Proof,
    presentation_request: MqttOpenId4VpRequest,
    proof_repository: Arc<dyn ProofRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    interaction_id: InteractionId,
    notification: Arc<Notify>,
) -> anyhow::Result<()> {
    let result = async {
        let identify_bytes = tokio::select! {
            resp = topics.identify.recv() => {
                resp?
            },
            // stop the flow if other transport was selected
            _ = notification.notified() => {
                tracing::debug!("Stopping MQTT verifier flow, other transport selected");

                return Ok(());
            }
        };

        notification.notify_waiters();

        tracing::debug!("got identify message");

        proof_repository
            .update_proof(
                &proof.id,
                UpdateProofRequest {
                    transport: Some("MQTT".into()),
                    ..Default::default()
                },
            )
            .await?;

        let identity_request = parse_identity_request(identify_bytes)?;
        let (encryption_key, decryption_key) =
            keypair.derive_session_secrets(identity_request.key, identity_request.nonce)?;

        let shared_key =
            PeerEncryption::new(encryption_key, decryption_key, identity_request.nonce);

        let client_id = presentation_request.client_id.clone();
        let nonce = presentation_request.nonce.clone();
        let identity_request_nonce = hex::encode(identity_request.nonce);

        let bytes = shared_key.encrypt(presentation_request)?;

        topics.presentation_definition.send(bytes).await?;

        tracing::debug!("presentation_definition is sent");

        let now = OffsetDateTime::now_utc();
        proof_repository
            .set_proof_state(
                &proof.id,
                ProofState {
                    created_date: now,
                    last_modified: now,
                    state: ProofStateEnum::Requested,
                },
            )
            .await?;

        let reject = async {
            loop {
                let Ok(reject) = topics.reject.recv().await else {
                    continue;
                };

                let Ok(timestamp) = shared_key.decrypt::<i64>(&reject) else {
                    continue;
                };

                let timestamp_date = OffsetDateTime::from_unix_timestamp(timestamp).unwrap();
                let now = OffsetDateTime::now_utc();

                let diff = now - timestamp_date;
                if diff < Duration::minutes(5) {
                    break;
                }
            }
        };

        let organisation = proof
            .schema
            .as_ref()
            .and_then(|schema| schema.organisation.as_ref())
            .ok_or(ExchangeProtocolError::Failed(
                "organisation is None".to_string(),
            ))?;

        tokio::select! {
            credential = topics.accept.recv() => {
                tracing::debug!("got accept message");

                let credential = credential?;

                let presentation_submission: MQTTOpenId4VpResponse = shared_key
                    .decrypt(&credential)
                    .context("Failed to decrypt presentation request")?;

                let now = OffsetDateTime::now_utc();

                interaction_repository
                    .update_interaction(Interaction {
                        id: interaction_id,
                        created_date: now,
                        last_modified: now,
                        host: None,
                        data: Some(
                            serde_json::to_vec(&MQTTOpenID4VPInteractionDataVerifier {
                                presentation_submission,
                                nonce,
                                client_id,
                                identity_request_nonce,
                            })
                            .context("failed to serialize presentation_submission")?,
                        ),
                        organisation: Some(organisation.clone()),
                    })
                    .await?;

                let _ = proof_repository
                    .set_proof_state(
                        &proof.id,
                        ProofState {
                            created_date: now,
                            last_modified: now,
                            state: ProofStateEnum::Accepted,
                        },
                    )
                    .await;
            },
            _ = reject => {
                tracing::debug!("got reject message");

                let now = OffsetDateTime::now_utc();
                let _ = proof_repository
                    .set_proof_state(
                        &proof.id,
                        ProofState {
                            created_date: now,
                            last_modified: now,
                            state: ProofStateEnum::Rejected,
                        },
                    )
                    .await;
            }
        }

        Ok(())
    }
    .await;

    if result.is_err() {
        let now = OffsetDateTime::now_utc();
        let _ = proof_repository
            .set_proof_state(
                &proof.id,
                ProofState {
                    created_date: now,
                    last_modified: now,
                    state: ProofStateEnum::Rejected,
                },
            )
            .await;
    }

    result
}

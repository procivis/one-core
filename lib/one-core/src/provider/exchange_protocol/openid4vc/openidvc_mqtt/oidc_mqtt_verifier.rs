use std::sync::Arc;

use anyhow::Context;
use shared_types::ProofId;
use time::{Duration, OffsetDateTime};

use crate::model::interaction::{Interaction, InteractionId};
use crate::model::proof::{ProofState, ProofStateEnum, UpdateProofRequest};
use crate::provider::exchange_protocol::openid4vc::key_agreement_key::KeyAgreementKey;
use crate::provider::exchange_protocol::openid4vc::mapper::parse_identity_request;
use crate::provider::exchange_protocol::openid4vc::model::{
    MQTTOpenID4VPInteractionDataVerifier, MQTTOpenId4VpResponse, OpenID4VPPresentationDefinition,
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

#[tracing::instrument(
    level = "debug",
    skip(
        topics,
        keypair,
        presentation_definition,
        proof_repository,
        interaction_repository,
    ),
    err(Debug)
)]
pub(super) async fn mqtt_verifier_flow(
    mut topics: Topics,
    keypair: KeyAgreementKey,
    proof_id: ProofId,
    presentation_definition: OpenID4VPPresentationDefinition,
    proof_repository: Arc<dyn ProofRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    interaction_id: InteractionId,
) -> anyhow::Result<()> {
    let result = async {
        let identify_bytes = topics.identify.recv().await?;

        tracing::debug!("got identify message");

        proof_repository
            .update_proof(
                &proof_id,
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

        let bytes = shared_key.encrypt(presentation_definition)?;

        topics.presentation_definition.send(bytes).await?;

        tracing::debug!("presentation_definition is sent");

        let now = OffsetDateTime::now_utc();
        proof_repository
            .set_proof_state(
                &proof_id,
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

                let Ok(timestamp) = shared_key
                    .decrypt::<i64>(&reject)
                else {
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

        tokio::select! {
            credential = topics.accept.recv() => {
                tracing::debug!("got accept message");

                let credential = credential?;

                let presentation_submission: MQTTOpenId4VpResponse = shared_key
                    .decrypt(&credential)
                    .context("Failed to decrypt presentation request")?;

                let now = OffsetDateTime::now_utc();
                interaction_repository.update_interaction(Interaction {
                    id: interaction_id,
                    created_date: now,
                    last_modified: now,
                    host: None,
                    data: Some(
                        serde_json::to_vec(&MQTTOpenID4VPInteractionDataVerifier { presentation_submission })
                            .context("failed to serialize presentation_submission")?
                    ),
                    organisation: None,
                }).await?;

                let _ = proof_repository
                    .set_proof_state(
                        &proof_id,
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
                        &proof_id,
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
                &proof_id,
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

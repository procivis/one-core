use std::sync::Arc;

use anyhow::Context;
use futures::future::{BoxFuture, Shared};
use one_crypto::utilities;
use time::{Duration, OffsetDateTime};
use tokio_util::sync::CancellationToken;

use super::set_proof_state;
use crate::config::core_config::TransportType;
use crate::model::did::Did;
use crate::model::interaction::{Interaction, InteractionId};
use crate::model::proof::{Proof, ProofStateEnum, UpdateProofRequest};
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::provider::exchange_protocol::error::ExchangeProtocolError;
use crate::provider::exchange_protocol::openid4vc::key_agreement_key::KeyAgreementKey;
use crate::provider::exchange_protocol::openid4vc::model::{
    ClientIdSchemaType, OpenID4VPAuthorizationRequest, OpenID4VPPresentationDefinition,
};
use crate::provider::exchange_protocol::openid4vc::openidvc_ble::mappers::parse_identity_request;
use crate::provider::exchange_protocol::openid4vc::openidvc_mqtt::model::{
    MQTTOpenID4VPInteractionDataVerifier, MQTTOpenId4VpResponse,
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
    presentation_definition: OpenID4VPPresentationDefinition,
    auth_fn: AuthenticationFn,
    did: Did,
    proof_repository: Arc<dyn ProofRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    interaction_id: InteractionId,
    cancellation_token: CancellationToken,
    callback: Option<Shared<BoxFuture<'static, ()>>>,
) -> anyhow::Result<()> {
    let result = async {
        let identify_bytes = tokio::select! {
            resp = topics.identify.recv() => {
                resp?
            },
            // stop the flow if other transport was selected
            _ = cancellation_token.cancelled() => {
                tracing::debug!("Stopping MQTT verifier flow, other transport selected");

                return Ok(());
            }
        };

        // we notify other transport that this was selected so they can cancel their work
        cancellation_token.cancel();

        tracing::debug!("got identify message");

        proof_repository
            .update_proof(
                &proof.id,
                UpdateProofRequest {
                    transport: Some(TransportType::Mqtt.to_string()),
                    ..Default::default()
                },
            )
            .await?;

        let identity_request = parse_identity_request(identify_bytes)?;
        let (encryption_key, decryption_key) =
            keypair.derive_session_secrets(identity_request.key, identity_request.nonce)?;

        let shared_key =
            PeerEncryption::new(encryption_key, decryption_key, identity_request.nonce);

        let request = OpenID4VPAuthorizationRequest {
            nonce: utilities::generate_nonce(),
            presentation_definition: presentation_definition.clone(),
            response_type: None,
            response_mode: None,
            client_id: did.did.to_string(),
            client_id_scheme: Some(ClientIdSchemaType::Did),
            client_metadata: None,
            response_uri: None,
            state: None,
        };

        let signed = request
            .as_signed_jwt(&did.did, auth_fn)
            .await
            .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))?;

        let bytes = shared_key.encrypt(&signed)?;
        topics.presentation_definition.send(bytes).await?;
        set_proof_state(&proof, ProofStateEnum::Requested, &*proof_repository).await?;

        tracing::debug!("presentation_definition is sent");

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
                                presentation_definition: presentation_definition.clone(),
                                presentation_submission,
                                nonce: request.nonce,
                                client_id: request.client_id,
                                identity_request_nonce: hex::encode(identity_request.nonce),
                            })
                            .context("failed to serialize presentation_submission")?,
                        ),
                        organisation: Some(organisation.clone()),
                    })
                    .await?;

                if let Some(callback) = callback {
                    callback.await;
                }
            },
            _ = reject => {
                tracing::debug!("got reject message");
                set_proof_state(&proof, ProofStateEnum::Rejected, &*proof_repository).await?;
            }
        }

        Ok(())
    }
    .await;

    if result.is_err() {
        set_proof_state(&proof, ProofStateEnum::Error, &*proof_repository).await?;
    }

    result
}

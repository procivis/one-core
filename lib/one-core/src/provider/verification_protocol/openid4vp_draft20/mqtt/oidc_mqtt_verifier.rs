use std::sync::Arc;

use futures::future::{BoxFuture, Shared};
use futures::FutureExt;
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::config::core_config::TransportType;
use crate::model::did::Did;
use crate::model::history::HistoryErrorMetadata;
use crate::model::interaction::InteractionId;
use crate::model::proof::{Proof, ProofStateEnum};
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::provider::mqtt_client::MqttTopic;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp_draft20::async_verifier_flow::{
    async_verifier_flow, never, set_proof_state_infallible, AsyncTransportHooks,
    AsyncVerifierFlowParams, FlowState,
};
use crate::provider::verification_protocol::openid4vp_draft20::ble::mappers::parse_identity_request;
use crate::provider::verification_protocol::openid4vp_draft20::ble::IdentityRequest;
use crate::provider::verification_protocol::openid4vp_draft20::key_agreement_key::KeyAgreementKey;
use crate::provider::verification_protocol::openid4vp_draft20::model::{
    OpenID4VPAuthorizationRequestParams, OpenID4VPPresentationDefinition,
};
use crate::provider::verification_protocol::openid4vp_draft20::mqtt::model::{
    MQTTOpenID4VPInteractionDataVerifier, MQTTOpenId4VpResponse,
};
use crate::provider::verification_protocol::openid4vp_draft20::peer_encryption::PeerEncryption;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::error::ErrorCode::BR_0000;

pub(super) struct Topics {
    pub(super) identify: Mutex<Box<dyn MqttTopic>>,
    pub(super) presentation_definition: Mutex<Box<dyn MqttTopic>>,
    pub(super) accept: Mutex<Box<dyn MqttTopic>>,
    pub(super) reject: Mutex<Box<dyn MqttTopic>>,
}

#[tracing::instrument(level = "debug", skip_all, err(Debug))]
#[allow(clippy::too_many_arguments)]
pub(super) async fn mqtt_verifier_flow(
    topics: Topics,
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
) -> Result<(), VerificationProtocolError> {
    let hooks = AsyncTransportHooks {
        wallet_connect: wallet_connect(topics, keypair),
        wallet_disconnect: never, // MQTT does not provide information about peers disconnecting
        wallet_reject,
        send_presentation_request,
        receive_presentation,
        interaction_data_from_response,
    };

    let flow_params = AsyncVerifierFlowParams {
        proof: &proof,
        presentation_definition,
        did: &did.did,
        interaction_id,
        proof_repository: &*proof_repository,
        interaction_repository: &*interaction_repository,
        transport_type: TransportType::Mqtt,
        cancellation_token,
    };

    let result = async_verifier_flow(flow_params, hooks, auth_fn).await;
    match &result {
        Ok(FlowState::Finished) => {
            if let Some(callback) = callback {
                callback.await;
            }
        }
        Err(ref err) => {
            let message = format!("MQTT verifier flow failure: {err}");
            info!(message);
            let error_metadata = HistoryErrorMetadata {
                error_code: BR_0000,
                message,
            };
            set_proof_state_infallible(
                &proof,
                ProofStateEnum::Error,
                Some(error_metadata),
                &*proof_repository,
            )
            .await;
        }
        Ok(_) => {} // cancel or reject -> nothing to do
    }
    Ok(())
}

struct MQTTVerifierContext {
    shared_key: PeerEncryption,
    identity_request: IdentityRequest,
    topics: Topics,
}
fn wallet_connect(
    topics: Topics,
    keypair: KeyAgreementKey,
) -> BoxFuture<'static, Result<MQTTVerifierContext, VerificationProtocolError>> {
    async {
        let identify_bytes = topics
            .identify
            .lock()
            .await
            .recv()
            .await
            .map_err(VerificationProtocolError::Transport)?;
        let identity_request =
            parse_identity_request(identify_bytes).map_err(VerificationProtocolError::Transport)?;
        let (encryption_key, decryption_key) = keypair
            .derive_session_secrets(identity_request.key, identity_request.nonce)
            .map_err(VerificationProtocolError::Transport)?;
        let shared_key =
            PeerEncryption::new(encryption_key, decryption_key, identity_request.nonce);
        Ok(MQTTVerifierContext {
            shared_key,
            identity_request,
            topics,
        })
    }
    .boxed()
}

fn wallet_reject(context: Arc<MQTTVerifierContext>) -> BoxFuture<'static, ()> {
    async move {
        loop {
            let Ok(reject) = context.topics.reject.lock().await.recv().await else {
                continue;
            };

            let Ok(timestamp) = context.shared_key.decrypt::<i64>(&reject) else {
                continue;
            };

            if let Ok(timestamp_date) = OffsetDateTime::from_unix_timestamp(timestamp) {
                let now = OffsetDateTime::now_utc();

                let diff = now - timestamp_date;
                if diff < Duration::minutes(5) {
                    break;
                }
            }
        }
    }
    .boxed()
}

fn send_presentation_request(
    request: String,
    context: Arc<MQTTVerifierContext>,
) -> BoxFuture<'static, Result<(), VerificationProtocolError>> {
    async move {
        let bytes = context
            .shared_key
            .encrypt(&request)
            .map_err(VerificationProtocolError::Transport)?;
        context
            .topics
            .presentation_definition
            .lock()
            .await
            .send(bytes)
            .await
            .map_err(VerificationProtocolError::Transport)
    }
    .boxed()
}

fn receive_presentation(
    context: Arc<MQTTVerifierContext>,
) -> BoxFuture<'static, Result<MQTTOpenId4VpResponse, VerificationProtocolError>> {
    (async move {
        let credential = context
            .topics
            .accept
            .lock()
            .await
            .recv()
            .await
            .map_err(VerificationProtocolError::Transport)?;
        context
            .shared_key
            .decrypt(&credential)
            .map_err(VerificationProtocolError::Transport)
    })
    .boxed()
}

fn interaction_data_from_response(
    nonce: String,
    presentation_definition: OpenID4VPPresentationDefinition,
    request: OpenID4VPAuthorizationRequestParams,
    submission: MQTTOpenId4VpResponse,
    context: Arc<MQTTVerifierContext>,
) -> Result<Vec<u8>, VerificationProtocolError> {
    serde_json::to_vec(&MQTTOpenID4VPInteractionDataVerifier {
        presentation_definition,
        presentation_submission: submission,
        nonce,
        client_id: request.client_id,
        identity_request_nonce: hex::encode(context.identity_request.nonce),
    })
    .map_err(|err| {
        VerificationProtocolError::Failed(format!(
            "failed to serialize presentation_submission: {err}"
        ))
    })
}

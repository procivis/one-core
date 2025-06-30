use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use futures::future::BoxFuture;
use shared_types::ProofId;
use time::{Duration, OffsetDateTime};
use tokio::select;
use tokio::sync::Mutex;
use tracing::Instrument;
use url::Url;

use super::model::{MQTTOpenID4VPInteractionDataVerifier, MQTTOpenId4VpResponse};
use crate::config::core_config::TransportType;
use crate::model::interaction::InteractionId;
use crate::model::proof::Proof;
use crate::provider::mqtt_client::{MqttClient, MqttTopic};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::draft20::model::OpenID4VP20AuthorizationRequest;
use crate::provider::verification_protocol::openid4vp::model::OpenID4VPPresentationDefinition;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::async_verifier_flow::{
    HolderSubmission, ProximityVerifierTransport,
};
use crate::provider::verification_protocol::openid4vp::proximity_draft00::ble::IdentityRequest;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::ble::mappers::parse_identity_request;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::mqtt::{
    ConfigParams, SubscriptionHandle,
};
use crate::provider::verification_protocol::openid4vp::proximity_draft00::peer_encryption::PeerEncryption;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::{KeyAgreementKey, mqtt};

pub(crate) struct MqttVerifier {
    mqtt_client: Arc<dyn MqttClient>,
    params: ConfigParams,
    handle: Mutex<HashMap<ProofId, SubscriptionHandle>>,
}

impl MqttVerifier {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(mqtt_client: Arc<dyn MqttClient>, params: ConfigParams) -> MqttVerifier {
        MqttVerifier {
            mqtt_client,
            params,
            handle: Mutex::new(HashMap::new()),
        }
    }

    async fn subscribe_to_topic(
        &self,
        topic: String,
    ) -> Result<Box<dyn MqttTopic>, VerificationProtocolError> {
        let (host, port) = mqtt::extract_host_and_port(&self.params.broker_url)?;

        self
            .mqtt_client
            .subscribe(
                host,
                port,
                topic.clone(),
            )
            .await
            .map_err(move |error| {
                tracing::error!(%error, "Failed to subscribe to `{topic}` topic during proof sharing");
                VerificationProtocolError::Failed(format!("Failed to subscribe to `{topic}` topic"))
            })
    }

    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(level = "debug", skip_all, err(Debug))]
    async fn start_detached_subscriber(
        &self,
        topic_prefix: String,
        proof_id: ProofId,
        flow: impl FnOnce(MqttVerifierTransport) -> BoxFuture<'static, ()> + Send + 'static,
    ) -> Result<(), VerificationProtocolError> {
        let (identify, presentation_definition, accept, reject) = tokio::try_join!(
            self.subscribe_to_topic(topic_prefix.clone() + "/presentation-submission/identify"),
            self.subscribe_to_topic(topic_prefix.clone() + "/presentation-definition"),
            self.subscribe_to_topic(topic_prefix.clone() + "/presentation-submission/accept"),
            self.subscribe_to_topic(topic_prefix + "/presentation-submission/reject"),
        )?;

        let topics = MqttVerifierTransport {
            identify,
            presentation_definition,
            accept,
            reject,
        };

        let handle = tokio::spawn(flow(topics).in_current_span());

        let old = self.handle.lock().await.insert(
            proof_id,
            SubscriptionHandle {
                task_handle: handle,
            },
        );

        if let Some(old) = old {
            old.task_handle.abort()
        };

        Ok(())
    }

    #[tracing::instrument(level = "debug", skip_all, err(Debug))]
    pub(crate) async fn schedule_verifier_flow(
        &self,
        key_agreement: &KeyAgreementKey,
        url_scheme: &str,
        interaction_id: InteractionId,
        proof_id: ProofId,
        flow: impl FnOnce(MqttVerifierTransport) -> BoxFuture<'static, ()> + Send + 'static,
    ) -> Result<Url, VerificationProtocolError> {
        let url = {
            let mut url: Url = format!("{url_scheme}://connect").parse().map_err(|e| {
                VerificationProtocolError::Failed(format!("Failed to parse url: `{e}`"))
            })?;
            url.query_pairs_mut()
                .append_pair("key", &hex::encode(key_agreement.public_key_bytes()))
                .append_pair(
                    "brokerUrl",
                    self.params.broker_url.as_str().trim_end_matches('/'),
                )
                .append_pair("topicId", &interaction_id.to_string());

            url
        };

        let topic_prefix = format!("/proof/{interaction_id}");
        self.start_detached_subscriber(topic_prefix, proof_id, flow)
            .await?;

        Ok(url)
    }

    pub(crate) async fn retract_proof(
        &self,
        proof: &Proof,
    ) -> Result<(), VerificationProtocolError> {
        if let Some(old) = self.handle.lock().await.remove(&proof.id) {
            old.task_handle.abort()
        };

        Ok(())
    }
}

pub(crate) struct MqttVerifierTransport {
    pub identify: Box<dyn MqttTopic>,
    pub presentation_definition: Box<dyn MqttTopic>,
    pub accept: Box<dyn MqttTopic>,
    pub reject: Box<dyn MqttTopic>,
}

pub(crate) struct MqttVerifierContext {
    identity_request: IdentityRequest,
    shared_key: PeerEncryption,
}

#[async_trait]
impl ProximityVerifierTransport for MqttVerifierTransport {
    type Context = MqttVerifierContext;
    type PresentationSubmission = MQTTOpenId4VpResponse;

    fn transport_type(&self) -> TransportType {
        TransportType::Mqtt
    }

    async fn wallet_connect(
        &mut self,
        key_agreement: &KeyAgreementKey,
    ) -> Result<Self::Context, VerificationProtocolError> {
        let identify_bytes = self
            .identify
            .recv()
            .await
            .map_err(VerificationProtocolError::Transport)?;
        let identity_request =
            parse_identity_request(identify_bytes).map_err(VerificationProtocolError::Transport)?;
        let (encryption_key, decryption_key) = key_agreement
            .derive_session_secrets(identity_request.key, identity_request.nonce)
            .map_err(VerificationProtocolError::Transport)?;
        let shared_key =
            PeerEncryption::new(encryption_key, decryption_key, identity_request.nonce);
        Ok(MqttVerifierContext {
            identity_request,
            shared_key,
        })
    }

    async fn send_presentation_request(
        &mut self,
        context: &Self::Context,
        signed_presentation_request: String,
    ) -> Result<(), VerificationProtocolError> {
        let bytes = context
            .shared_key
            .encrypt(&signed_presentation_request)
            .map_err(VerificationProtocolError::Transport)?;
        self.presentation_definition
            .send(bytes)
            .await
            .map_err(VerificationProtocolError::Transport)
    }

    async fn receive_presentation(
        &mut self,
        context: &mut Self::Context,
    ) -> Result<HolderSubmission<Self::PresentationSubmission>, VerificationProtocolError> {
        let response = select! {
            biased;
            _ = wallet_reject(&mut *self.reject, &context.shared_key) => {
                return Ok(HolderSubmission::Rejection)
            }
            response = self.accept.recv() => response
        }
        .map_err(VerificationProtocolError::Transport)?;
        let decrypted_presentation = context
            .shared_key
            .decrypt(&response)
            .map_err(VerificationProtocolError::Transport)?;
        Ok(HolderSubmission::Presentation(decrypted_presentation))
    }

    fn interaction_data_from_submission(
        &self,
        context: Self::Context,
        nonce: String,
        presentation_definition: OpenID4VPPresentationDefinition,
        request: OpenID4VP20AuthorizationRequest,
        presentation_submission: Self::PresentationSubmission,
    ) -> Result<Vec<u8>, VerificationProtocolError> {
        serde_json::to_vec(&MQTTOpenID4VPInteractionDataVerifier {
            presentation_definition,
            presentation_submission,
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

    async fn clean_up(&self) {
        // nothing to do
    }
}

async fn wallet_reject(rejection_topic: &mut dyn MqttTopic, shared_key: &PeerEncryption) {
    loop {
        let Ok(reject) = rejection_topic.recv().await else {
            continue;
        };

        let Ok(timestamp) = shared_key.decrypt::<i64>(&reject) else {
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

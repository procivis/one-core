use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use futures::future::BoxFuture;
use shared_types::{InteractionId, ProofId};
use time::{Duration, OffsetDateTime};
use tokio::select;
use tokio::sync::Mutex;
use tracing::Instrument;
use url::Url;

use super::model::{MQTTOpenID4VPInteractionDataVerifier, MQTTVerifierProtocolData};
use super::{ConfigParams, SubscriptionHandle, extract_host_and_port};
use crate::config::core_config::TransportType;
use crate::model::proof::Proof;
use crate::proto::mqtt_client::{MqttClient, MqttTopic};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::KeyAgreementKey;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::async_verifier_flow::{
    HolderResponse, HolderSubmission, ProximityVerifierTransport, SubmissionData,
};
use crate::provider::verification_protocol::openid4vp::proximity_draft00::dto::{
    IdentityRequest, ProtocolVersion, WithProtocolVersion,
};
use crate::provider::verification_protocol::openid4vp::proximity_draft00::peer_encryption::PeerEncryption;

pub(crate) struct MqttVerifier {
    mqtt_client: Arc<dyn MqttClient>,
    params: ConfigParams,
    handle: Mutex<HashMap<ProofId, SubscriptionHandle>>,
}

impl MqttVerifier {
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
        let (host, port) = extract_host_and_port(&self.params.broker_url)?;

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
    identify: Box<dyn MqttTopic>,
    presentation_definition: Box<dyn MqttTopic>,
    accept: Box<dyn MqttTopic>,
    reject: Box<dyn MqttTopic>,
}

pub(crate) struct MqttVerifierContext {
    identity_request: IdentityRequest,
    shared_key: PeerEncryption,
    enveloping: bool,
}

impl WithProtocolVersion for MqttVerifierContext {
    fn protocol_version(&self) -> ProtocolVersion {
        self.identity_request.version
    }
}

#[async_trait]
impl ProximityVerifierTransport for MqttVerifierTransport {
    type Context = MqttVerifierContext;

    fn transport_type(&self) -> TransportType {
        TransportType::Mqtt
    }

    async fn wallet_connect(
        &mut self,
        key_agreement: &KeyAgreementKey,
    ) -> Result<Self::Context, VerificationProtocolError> {
        let (identify_bytes, enveloped) = self
            .identify
            .recv()
            .await
            .map_err(VerificationProtocolError::Transport)?;
        let identity_request =
            IdentityRequest::parse(identify_bytes).map_err(VerificationProtocolError::Transport)?;
        let (encryption_key, decryption_key) = key_agreement
            .derive_session_secrets(identity_request.key, identity_request.nonce)
            .map_err(VerificationProtocolError::Transport)?;
        let shared_key =
            PeerEncryption::new(encryption_key, decryption_key, identity_request.nonce);
        Ok(MqttVerifierContext {
            identity_request,
            shared_key,
            enveloping: enveloped,
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
            .send(bytes, context.enveloping)
            .await
            .map_err(VerificationProtocolError::Transport)
    }

    async fn receive_presentation(
        &mut self,
        context: &mut Self::Context,
    ) -> Result<HolderResponse, VerificationProtocolError> {
        let (response, enveloped) = select! {
            biased;
            _ = wallet_reject(&mut *self.reject, &context.shared_key) => {
                return Ok(HolderResponse::Rejection)
            }
            response = self.accept.recv() => response
        }
        .map_err(VerificationProtocolError::Transport)?;

        if enveloped != context.enveloping {
            tracing::warn!(
                "Mismatched enveloping, identity_request: {}, presentation: {enveloped}",
                context.enveloping
            );
        }

        Ok(HolderResponse::Submission(
            match context.identity_request.version {
                ProtocolVersion::V1 => HolderSubmission::V1(
                    context
                        .shared_key
                        .decrypt(&response)
                        .map_err(VerificationProtocolError::Transport)?,
                ),
                ProtocolVersion::V2 => HolderSubmission::V2(
                    context
                        .shared_key
                        .decrypt(&response)
                        .map_err(VerificationProtocolError::Transport)?,
                ),
            },
        ))
    }

    fn interaction_data_from_submission(
        &self,
        context: Self::Context,
        nonce: String,
        data: SubmissionData,
    ) -> Result<Vec<u8>, VerificationProtocolError> {
        let interaction_data = match data {
            SubmissionData::V1 {
                request,
                submission,
                presentation_definition,
            } => MQTTOpenID4VPInteractionDataVerifier {
                nonce,
                client_id: request.client_id,
                mdoc_generated_nonce: Some(hex::encode(context.identity_request.nonce)),
                protocol_data: MQTTVerifierProtocolData::V1 {
                    submission,
                    presentation_definition,
                },
            },
            SubmissionData::V2 {
                request,
                submission,
                dcql_query,
            } => MQTTOpenID4VPInteractionDataVerifier {
                nonce,
                client_id: request.client_id,
                mdoc_generated_nonce: None,
                protocol_data: MQTTVerifierProtocolData::V2 {
                    dcql_query,
                    submission,
                },
            },
        };

        serde_json::to_vec(&interaction_data).map_err(|err| {
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
        let Ok((reject, _)) = rejection_topic.recv().await else {
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

#[cfg(test)]
mod test {
    use mockall::predicate::{always, eq};
    use similar_asserts::assert_eq;

    use super::*;
    use crate::proto::mqtt_client::MockMqttTopic;

    #[tokio::test]
    async fn test_mqtt_verifier_transport_enveloped() {
        let mut identify = MockMqttTopic::new();
        identify.expect_recv().once().return_once(|| {
            Ok((
                IdentityRequest {
                    key: [0u8; 32],
                    nonce: [0u8; 12],
                    version: ProtocolVersion::V1,
                }
                .encode(),
                true,
            ))
        });
        let mut presentation_definition = MockMqttTopic::new();
        presentation_definition
            .expect_send()
            .once()
            .with(always(), eq(true))
            .returning(|_, _| Ok(()));

        let mut transport = MqttVerifierTransport {
            identify: Box::new(identify),
            presentation_definition: Box::new(presentation_definition),
            accept: Box::new(MockMqttTopic::new()),
            reject: Box::new(MockMqttTopic::new()),
        };

        let context = transport
            .wallet_connect(&KeyAgreementKey::new_random())
            .await
            .unwrap();

        assert_eq!(context.enveloping, true);

        transport
            .send_presentation_request(&context, "request".to_string())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_mqtt_verifier_transport_non_enveloped() {
        let mut identify = MockMqttTopic::new();
        identify.expect_recv().once().return_once(|| {
            Ok((
                IdentityRequest {
                    key: [0u8; 32],
                    nonce: [0u8; 12],
                    version: ProtocolVersion::V1,
                }
                .encode(),
                false,
            ))
        });
        let mut presentation_definition = MockMqttTopic::new();
        presentation_definition
            .expect_send()
            .once()
            .with(always(), eq(false))
            .returning(|_, _| Ok(()));

        let mut transport = MqttVerifierTransport {
            identify: Box::new(identify),
            presentation_definition: Box::new(presentation_definition),
            accept: Box::new(MockMqttTopic::new()),
            reject: Box::new(MockMqttTopic::new()),
        };

        let context = transport
            .wallet_connect(&KeyAgreementKey::new_random())
            .await
            .unwrap();

        assert_eq!(context.enveloping, false);

        transport
            .send_presentation_request(&context, "request".to_string())
            .await
            .unwrap();
    }
}

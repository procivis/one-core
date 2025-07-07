use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use dto::OpenID4VPMqttQueryParams;
use model::{MQTTOpenID4VPInteractionDataHolder, MQTTOpenId4VpResponse, MQTTSessionKeys};
use one_crypto::utilities::generate_random_bytes;
use serde::Deserialize;
use serde_json::Value;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::key_agreement_key::KeyAgreementKey;
use crate::config::core_config::TransportType;
use crate::provider::mqtt_client::{MqttClient, MqttTopic};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::draft20::model::OpenID4VP20AuthorizationRequest;
use crate::provider::verification_protocol::openid4vp::model::PresentationSubmissionMappingDTO;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::ble::IdentityRequest;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::holder_flow::{
    HolderCommonVPInteractionData, ProximityHolderTransport,
};
use crate::provider::verification_protocol::openid4vp::proximity_draft00::peer_encryption::PeerEncryption;
pub mod dto;
pub mod model;
pub(crate) mod oidc_mqtt_verifier;

#[cfg(test)]
mod test;

pub(crate) struct MqttHolderTransport {
    url_scheme: String,
    mqtt_client: Arc<dyn MqttClient>,
}

impl MqttHolderTransport {
    pub(crate) fn new(url_scheme: String, mqtt_client: Arc<dyn MqttClient>) -> Self {
        Self {
            url_scheme,
            mqtt_client,
        }
    }
}

pub(crate) struct MqttHolderContext {
    presentation_definition_topic: Box<dyn MqttTopic>,
    identity_request_nonce: String,
    session_keys: MQTTSessionKeys,
    encryption: PeerEncryption,
    topic_id: Uuid,
    broker_url: Url,
}

#[async_trait]
impl ProximityHolderTransport for MqttHolderTransport {
    type Context = MqttHolderContext;

    fn can_handle(&self, url: &Url) -> bool {
        let query_has_key = |name| url.query_pairs().any(|(key, _)| name == key);

        self.url_scheme == url.scheme()
            && query_has_key("brokerUrl")
            && query_has_key("key")
            && query_has_key("topicId")
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Mqtt
    }

    async fn setup(&self, url: Url) -> Result<Self::Context, VerificationProtocolError> {
        let query = url
            .query()
            .ok_or(VerificationProtocolError::InvalidRequest(
                "Query cannot be empty".to_string(),
            ))?;
        let OpenID4VPMqttQueryParams {
            broker_url,
            key,
            topic_id,
        } = serde_qs::from_str(query)
            .map_err(|e| VerificationProtocolError::InvalidRequest(e.to_string()))?;
        let (host, port) = extract_host_and_port(&broker_url)?;

        let verifier_public_key = hex::decode(&key)
            .context("Failed to decode verifier public key")
            .map_err(VerificationProtocolError::Transport)?
            .as_slice()
            .try_into()
            .context("Invalid verifier public key length")
            .map_err(VerificationProtocolError::Transport)?;

        let session_keys = generate_session_keys(verifier_public_key)?;
        let encryption = PeerEncryption::new(
            session_keys.sender_key.clone(),
            session_keys.receiver_key.clone(),
            session_keys.nonce,
        );
        let identity_request = IdentityRequest {
            key: session_keys.public_key.to_owned(),
            nonce: session_keys.nonce.to_owned(),
        };
        let identity_request_nonce = hex::encode(identity_request.nonce);

        let identify_topic = self
            .mqtt_client
            .subscribe(
                host.to_string(),
                port,
                format!("/proof/{topic_id}/presentation-submission/identify"),
            )
            .await
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        identify_topic
            .send(identity_request.encode())
            .await
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        let presentation_definition_topic = self
            .mqtt_client
            .subscribe(
                host.to_string(),
                port,
                format!("/proof/{topic_id}/presentation-definition"),
            )
            .await
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;
        Ok(MqttHolderContext {
            presentation_definition_topic,
            identity_request_nonce,
            session_keys,
            encryption,
            topic_id,
            broker_url,
        })
    }

    async fn receive_authz_request_token(
        &self,
        context: &mut Self::Context,
    ) -> Result<String, VerificationProtocolError> {
        let presentation_request_bytes = context
            .presentation_definition_topic
            .recv()
            .await
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;
        context
            .encryption
            .decrypt(&presentation_request_bytes)
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))
    }

    fn interaction_data_from_authz_request(
        &self,
        authz_request: OpenID4VP20AuthorizationRequest,
        context: Self::Context,
    ) -> Result<Vec<u8>, VerificationProtocolError> {
        let (host, port) = extract_host_and_port(&context.broker_url)?;
        let mqtt_interaction_data = MQTTOpenID4VPInteractionDataHolder {
            broker_url: host,
            broker_port: port,
            client_id: authz_request.client_id,
            nonce: authz_request
                .nonce
                .ok_or(VerificationProtocolError::Failed(
                    "missing nonce".to_string(),
                ))?,
            session_keys: context.session_keys,
            presentation_definition: authz_request.presentation_definition,
            identity_request_nonce: context.identity_request_nonce,
            topic_id: context.topic_id,
        };
        serde_json::to_vec(&mqtt_interaction_data)
            .map_err(|err| VerificationProtocolError::Failed(format!("Interaction data: {err}")))
    }

    fn parse_interaction_data(
        &self,
        interaction_data: Value,
    ) -> Result<HolderCommonVPInteractionData, VerificationProtocolError> {
        let interaction_data: MQTTOpenID4VPInteractionDataHolder =
            serde_json::from_value(interaction_data)
                .map_err(VerificationProtocolError::JsonError)?;

        Ok(HolderCommonVPInteractionData {
            client_id: interaction_data.client_id,
            presentation_definition: interaction_data.presentation_definition,
            nonce: interaction_data.nonce,
            identity_request_nonce: Some(interaction_data.identity_request_nonce),
        })
    }

    async fn submit_presentation(
        &self,
        vp_token: String,
        presentation_submission: PresentationSubmissionMappingDTO,
        interaction_data: Value,
    ) -> Result<(), VerificationProtocolError> {
        let interaction_data: MQTTOpenID4VPInteractionDataHolder =
            serde_json::from_value(interaction_data)
                .map_err(VerificationProtocolError::JsonError)?;

        let response = MQTTOpenId4VpResponse {
            vp_token,
            presentation_submission,
        };

        let encryption = PeerEncryption::new(
            interaction_data.session_keys.sender_key,
            interaction_data.session_keys.receiver_key,
            interaction_data.session_keys.nonce,
        );

        let encrypted = encryption
            .encrypt(&response)
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        let presentation_submission_topic = self
            .mqtt_client
            .subscribe(
                interaction_data.broker_url.to_string(),
                interaction_data.broker_port,
                format!(
                    "/proof/{}/presentation-submission/accept",
                    interaction_data.topic_id
                ),
            )
            .await
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        presentation_submission_topic
            .send(encrypted)
            .await
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))
    }

    async fn reject_proof(&self, interaction_data: Value) -> Result<(), VerificationProtocolError> {
        let interaction_data: MQTTOpenID4VPInteractionDataHolder =
            serde_json::from_value(interaction_data)
                .map_err(VerificationProtocolError::JsonError)?;

        let encryption = PeerEncryption::new(
            interaction_data.session_keys.sender_key,
            interaction_data.session_keys.receiver_key,
            interaction_data.session_keys.nonce,
        );

        let now = OffsetDateTime::now_utc().unix_timestamp();
        let encrypted = encryption
            .encrypt(&now)
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        let reject_topic_name = format!(
            "/proof/{}/presentation-submission/reject",
            interaction_data.topic_id
        );

        let reject_topic = self
            .mqtt_client
            .subscribe(
                interaction_data.broker_url,
                interaction_data.broker_port,
                reject_topic_name,
            )
            .await
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        reject_topic
            .send(encrypted)
            .await
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfigParams {
    broker_url: Url,
}

struct SubscriptionHandle {
    task_handle: tokio::task::JoinHandle<()>,
}

fn generate_session_keys(
    verifier_public_key: [u8; 32],
) -> Result<MQTTSessionKeys, VerificationProtocolError> {
    let key_agreement_key = KeyAgreementKey::new_random();
    let public_key = key_agreement_key.public_key_bytes();
    let nonce = generate_random_bytes::<12>();

    let (receiver_key, sender_key) = key_agreement_key
        .derive_session_secrets(verifier_public_key, nonce)
        .map_err(VerificationProtocolError::Transport)?;

    Ok(MQTTSessionKeys {
        public_key,
        receiver_key,
        sender_key,
        nonce,
    })
}

fn extract_host_and_port(url: &Url) -> Result<(String, u16), VerificationProtocolError> {
    url.host_str()
        .map(ToString::to_string)
        .zip(url.port())
        .ok_or_else(|| {
            VerificationProtocolError::Failed(format!("Invalid URL `{url}`. Missing host or port"))
        })
}

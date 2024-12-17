use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::provider::exchange_protocol::openid4vc::model::{
    OpenID4VPPresentationDefinition, PresentationSubmissionMappingDTO,
};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MQTTSessionKeys {
    pub public_key: [u8; 32],
    pub receiver_key: [u8; 32],
    pub sender_key: [u8; 32],
    pub nonce: [u8; 12],
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MQTTOpenID4VPInteractionData {
    pub broker_url: String,
    pub broker_port: u16,
    pub client_id: String,
    pub nonce: String,
    pub identity_request_nonce: String,
    pub session_keys: MQTTSessionKeys,
    pub presentation_definition: Option<OpenID4VPPresentationDefinition>,
    pub topic_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MQTTOpenId4VpResponse {
    pub vp_token: String,
    pub presentation_submission: PresentationSubmissionMappingDTO,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MQTTOpenID4VPInteractionDataVerifier {
    pub presentation_definition: OpenID4VPPresentationDefinition,
    pub presentation_submission: MQTTOpenId4VpResponse,
    pub nonce: String,
    pub identity_request_nonce: String,
    pub client_id: String,
}

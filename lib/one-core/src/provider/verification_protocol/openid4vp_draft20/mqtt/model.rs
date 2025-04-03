use secrecy::SecretSlice;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::common_mapper::secret_slice;
use crate::provider::verification_protocol::openid4vp_draft20::model::{
    OpenID4VPPresentationDefinition, PresentationSubmissionMappingDTO,
};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MQTTSessionKeys {
    pub public_key: [u8; 32],
    #[serde(with = "secret_slice")]
    pub receiver_key: SecretSlice<u8>,
    #[serde(with = "secret_slice")]
    pub sender_key: SecretSlice<u8>,
    pub nonce: [u8; 12],
}

/// Interaction data used for OpenID4VP (MQTT) on holder side
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MQTTOpenID4VPInteractionDataHolder {
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

/// Interaction data used for OpenID4VP (MQTT) on verifier side
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MQTTOpenID4VPInteractionDataVerifier {
    pub presentation_definition: OpenID4VPPresentationDefinition,
    pub presentation_submission: MQTTOpenId4VpResponse,
    pub nonce: String,
    pub identity_request_nonce: String,
    pub client_id: String,
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::provider::verification_protocol::openid4vp_draft20::model::OpenID4VPVerifierInteractionContent;
    use crate::provider::verification_protocol::{
        deserialize_interaction_data, serialize_interaction_data,
    };

    #[test]
    fn test_serialization_into_common_interaction_data_structure() {
        let data = MQTTOpenID4VPInteractionDataVerifier {
            nonce: "nonce".to_string(),
            identity_request_nonce: "identity_request_nonce".to_string(),
            presentation_submission: MQTTOpenId4VpResponse {
                vp_token: "vp_token".to_string(),
                presentation_submission: PresentationSubmissionMappingDTO {
                    id: "id".to_string(),
                    definition_id: "definition_id".to_string(),
                    descriptor_map: vec![],
                },
            },
            presentation_definition: OpenID4VPPresentationDefinition {
                id: Uuid::new_v4().to_string(),
                input_descriptors: vec![],
            },
            client_id: "client_id".to_string(),
        };

        let serialized = serialize_interaction_data(&data).unwrap();

        deserialize_interaction_data::<OpenID4VPVerifierInteractionContent>(Some(&serialized))
            .unwrap();
    }
}

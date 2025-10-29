use dcql::DcqlQuery;
use secrecy::SecretSlice;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::mapper::secret_slice;
use crate::provider::verification_protocol::openid4vp::model::DcqlSubmission;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub(crate) struct MQTTSessionKeys {
    pub public_key: [u8; 32],
    #[serde(with = "secret_slice")]
    pub receiver_key: SecretSlice<u8>,
    #[serde(with = "secret_slice")]
    pub sender_key: SecretSlice<u8>,
    pub nonce: [u8; 12],
}

/// Interaction data used for OpenID4VP (MQTT) on holder side
#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct MQTTOpenID4VPInteractionDataHolder {
    pub broker_url: String,
    pub broker_port: u16,
    pub client_id: String,
    pub nonce: String,
    pub identity_request_nonce: String,
    pub session_keys: MQTTSessionKeys,
    pub dcql_query: Option<DcqlQuery>,
    pub topic_id: Uuid,
}

/// Interaction data used for OpenID4VP (MQTT) on verifier side
#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct MQTTOpenID4VPInteractionDataVerifier {
    pub dcql_query: DcqlQuery,
    pub presentation_submission: DcqlSubmission,
    pub nonce: String,
    pub identity_request_nonce: String,
    pub client_id: String,
}

#[cfg(test)]
mod tests {

    use std::collections::HashMap;

    use super::*;
    use crate::provider::verification_protocol::openid4vp::model::OpenID4VPVerifierInteractionContent;
    use crate::provider::verification_protocol::{
        deserialize_interaction_data, serialize_interaction_data,
    };

    #[test]
    fn test_serialization_into_common_interaction_data_structure() {
        let data = MQTTOpenID4VPInteractionDataVerifier {
            nonce: "nonce".to_string(),
            identity_request_nonce: "identity_request_nonce".to_string(),
            presentation_submission: DcqlSubmission {
                vp_token: HashMap::from([("id".to_string(), vec!["token".to_string()])]),
            },
            dcql_query: DcqlQuery {
                credentials: vec![],
                credential_sets: None,
            },
            client_id: "client_id".to_string(),
        };

        let serialized = serialize_interaction_data(&data).unwrap();

        deserialize_interaction_data::<OpenID4VPVerifierInteractionContent>(Some(&serialized))
            .unwrap();
    }
}

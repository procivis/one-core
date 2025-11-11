use dcql::DcqlQuery;
use secrecy::SecretSlice;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::mapper::secret_slice;
use crate::provider::verification_protocol::openid4vp::model::{
    DcqlSubmission, OpenID4VPPresentationDefinition, PexSubmission,
};

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
    #[serde(flatten)]
    pub protocol_data: MQTTVerifierProtocolData,
    pub nonce: String,
    pub mdoc_generated_nonce: Option<String>,
    pub client_id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub(crate) enum MQTTVerifierProtocolData {
    V1 {
        submission: PexSubmission,
        presentation_definition: OpenID4VPPresentationDefinition,
    },
    V2 {
        submission: DcqlSubmission,
        dcql_query: DcqlQuery,
    },
}

#[cfg(test)]
mod tests {

    use std::collections::HashMap;

    use similar_asserts::assert_eq;

    use super::*;
    use crate::provider::verification_protocol::openid4vp::model::{
        OpenID4VPVerifierInteractionContent, PresentationSubmissionMappingDTO,
    };
    use crate::provider::verification_protocol::{
        deserialize_interaction_data, serialize_interaction_data,
    };

    #[test]
    fn test_serialization_v1_into_common_interaction_data_structure() {
        let presentation_definition = OpenID4VPPresentationDefinition {
            id: "id".to_string(),
            input_descriptors: vec![],
        };
        let data = MQTTOpenID4VPInteractionDataVerifier {
            client_id: "did:test:id".to_string(),
            nonce: "nonce".to_string(),
            mdoc_generated_nonce: None,
            protocol_data: MQTTVerifierProtocolData::V1 {
                submission: PexSubmission {
                    vp_token: vec!["vp_token".to_string()],
                    presentation_submission: PresentationSubmissionMappingDTO {
                        id: "id".to_string(),
                        definition_id: "definition_id".to_string(),
                        descriptor_map: vec![],
                    },
                },
                presentation_definition: presentation_definition.to_owned(),
            },
        };

        let serialized = serialize_interaction_data(&data).unwrap();

        let deserialized: OpenID4VPVerifierInteractionContent =
            deserialize_interaction_data(Some(&serialized)).unwrap();

        assert_eq!(deserialized.client_id, "did:test:id");
        assert_eq!(deserialized.nonce, "nonce");
        assert_eq!(
            deserialized.presentation_definition,
            Some(presentation_definition)
        );
        assert_eq!(deserialized.dcql_query, None);
    }

    #[test]
    fn test_serialization_v2_into_common_interaction_data_structure() {
        let dcql_query = DcqlQuery {
            credentials: vec![],
            credential_sets: None,
        };
        let data = MQTTOpenID4VPInteractionDataVerifier {
            nonce: "nonce".to_string(),
            client_id: "client_id".to_string(),
            mdoc_generated_nonce: None,
            protocol_data: MQTTVerifierProtocolData::V2 {
                submission: DcqlSubmission {
                    vp_token: HashMap::from([("id".to_string(), vec!["token".to_string()])]),
                },
                dcql_query: dcql_query.to_owned(),
            },
        };

        let serialized = serialize_interaction_data(&data).unwrap();

        let deserialized: OpenID4VPVerifierInteractionContent =
            deserialize_interaction_data(Some(&serialized)).unwrap();

        assert_eq!(deserialized.client_id, "client_id");
        assert_eq!(deserialized.nonce, "nonce");
        assert_eq!(deserialized.presentation_definition, None);
        assert_eq!(deserialized.dcql_query, Some(dcql_query));
    }
}

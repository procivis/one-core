use dcql::DcqlQuery;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::BLEPeer;
use crate::provider::verification_protocol::openid4vp::draft20::model::OpenID4VP20AuthorizationRequest;
use crate::provider::verification_protocol::openid4vp::final1_0::model::AuthorizationRequest;
use crate::provider::verification_protocol::openid4vp::model::{
    DcqlSubmission, OpenID4VPPresentationDefinition, PexSubmission,
};

/// Interaction data used for OpenID4VP over BLE
#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct BLEOpenID4VPInteractionDataHolder {
    pub client_id: String,
    pub nonce: String,
    pub task_id: Uuid,
    pub peer: BLEPeer,
    pub identity_request_nonce: Option<String>,
    pub openid_request: AuthorizationRequest,
    pub presentation_submission: Option<DcqlSubmission>,
    pub dcql_query: DcqlQuery,
}

/// Interaction data used for OpenID4VP over BLE
#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct BLEOpenID4VPInteractionDataVerifier {
    pub client_id: String,
    pub nonce: String,
    pub task_id: Uuid,
    pub peer: BLEPeer,
    pub mdoc_generated_nonce: Option<String>,
    #[serde(flatten)]
    pub protocol_data: BLEVerifierProtocolData,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
#[expect(clippy::large_enum_variant)]
pub(crate) enum BLEVerifierProtocolData {
    V1 {
        request: OpenID4VP20AuthorizationRequest,
        submission: Option<PexSubmission>,
        presentation_definition: OpenID4VPPresentationDefinition,
    },
    V2 {
        request: AuthorizationRequest,
        submission: Option<DcqlSubmission>,
        dcql_query: DcqlQuery,
    },
}

#[cfg(test)]
mod tests {
    use secrecy::SecretSlice;
    use similar_asserts::assert_eq;

    use super::*;
    use crate::proto::bluetooth_low_energy::low_level::dto::DeviceInfo;
    use crate::provider::verification_protocol::openid4vp::model::{
        ClientIdScheme, OpenID4VPVerifierInteractionContent,
    };
    use crate::provider::verification_protocol::openid4vp::proximity_draft00::peer_encryption::PeerEncryption;
    use crate::provider::verification_protocol::{
        deserialize_interaction_data, serialize_interaction_data,
    };

    #[test]
    fn test_serialization_v1_into_common_interaction_data_structure() {
        let presentation_definition = OpenID4VPPresentationDefinition {
            id: "id".to_string(),
            input_descriptors: vec![],
        };
        let data = BLEOpenID4VPInteractionDataVerifier {
            client_id: "did:test:id".to_string(),
            nonce: "nonce".to_string(),
            task_id: Uuid::new_v4(),
            peer: BLEPeer {
                device_info: DeviceInfo::new("address".to_string(), 16),
                peer_encryption: PeerEncryption::new(
                    SecretSlice::from(vec![0; 32]),
                    SecretSlice::from(vec![0; 32]),
                    [0; 12],
                ),
            },
            mdoc_generated_nonce: None,
            protocol_data: BLEVerifierProtocolData::V1 {
                request: OpenID4VP20AuthorizationRequest {
                    client_id: "did:test:id".to_string(),
                    client_id_scheme: Some(ClientIdScheme::Did),
                    state: None,
                    nonce: None,
                    response_type: None,
                    response_mode: None,
                    response_uri: None,
                    client_metadata: None,
                    client_metadata_uri: None,
                    redirect_uri: None,
                    presentation_definition: Some(presentation_definition.clone()),
                    presentation_definition_uri: None,
                },
                submission: None,
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
        let data = BLEOpenID4VPInteractionDataVerifier {
            client_id: "client_id".to_string(),
            nonce: "nonce".to_string(),
            task_id: Uuid::new_v4(),
            peer: BLEPeer {
                device_info: DeviceInfo::new("address".to_string(), 16),
                peer_encryption: PeerEncryption::new(
                    SecretSlice::from(vec![0; 32]),
                    SecretSlice::from(vec![0; 32]),
                    [0; 12],
                ),
            },
            mdoc_generated_nonce: None,
            protocol_data: BLEVerifierProtocolData::V2 {
                request: AuthorizationRequest {
                    client_id: "client_id".to_string(),
                    state: None,
                    nonce: None,
                    response_type: None,
                    response_mode: None,
                    response_uri: None,
                    client_metadata: None,
                    redirect_uri: None,
                    dcql_query: Some(dcql_query.clone()),
                },
                submission: None,
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

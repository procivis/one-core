use serde::{Deserialize, Serialize};
use standardized_types::openid4vp::dcql::DcqlQuery;
use standardized_types::openid4vp::{AuthorizationRequest, VpTokenResponse};
use uuid::Uuid;

use super::BLEPeer;

/// Interaction data used for OpenID4VP over BLE
#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct BLEOpenID4VPInteractionDataHolder {
    pub client_id: String,
    pub nonce: String,
    pub task_id: Uuid,
    pub peer: BLEPeer,
    pub identity_request_nonce: Option<String>,
    pub openid_request: AuthorizationRequest,
    pub presentation_submission: Option<VpTokenResponse>,
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
pub(crate) enum BLEVerifierProtocolData {
    // Proximity protocol V1 removed
    // V1,
    V2 {
        request: AuthorizationRequest,
        submission: Option<VpTokenResponse>,
        dcql_query: DcqlQuery,
    },
}

#[cfg(test)]
mod tests {
    use secrecy::SecretSlice;
    use similar_asserts::assert_eq;

    use super::*;
    use crate::proto::bluetooth_low_energy::low_level::dto::DeviceInfo;
    use crate::provider::verification_protocol::openid4vp::model::OpenID4VPVerifierInteractionContent;
    use crate::provider::verification_protocol::openid4vp::proximity_draft00::peer_encryption::PeerEncryption;
    use crate::provider::verification_protocol::{
        deserialize_interaction_data, serialize_interaction_data,
    };

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
                    dcql_query: dcql_query.clone(),
                    redirect_uri: None,
                    verifier_info: vec![],
                    transaction_data: vec![],
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
        assert_eq!(deserialized.dcql_query, dcql_query);
    }
}

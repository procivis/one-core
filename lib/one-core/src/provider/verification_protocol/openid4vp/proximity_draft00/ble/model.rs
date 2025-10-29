use dcql::DcqlQuery;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::BLEPeer;
use crate::provider::verification_protocol::openid4vp::final1_0::model::AuthorizationRequest;
use crate::provider::verification_protocol::openid4vp::model::DcqlSubmission;

/// Interaction data used for OpenID4VP over BLE
/// used on both holder and verifier side
#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct BLEOpenID4VPInteractionData {
    pub client_id: String,
    pub nonce: String,
    pub task_id: Uuid,
    pub peer: BLEPeer,
    pub identity_request_nonce: Option<String>,
    pub openid_request: AuthorizationRequest,
    pub presentation_submission: Option<DcqlSubmission>,
    pub dcql_query: DcqlQuery,
}

#[cfg(test)]
mod tests {
    use secrecy::SecretSlice;

    use super::*;
    use crate::proto::bluetooth_low_energy::low_level::dto::DeviceInfo;
    use crate::provider::verification_protocol::openid4vp::model::OpenID4VPVerifierInteractionContent;
    use crate::provider::verification_protocol::openid4vp::proximity_draft00::peer_encryption::PeerEncryption;
    use crate::provider::verification_protocol::{
        deserialize_interaction_data, serialize_interaction_data,
    };

    #[test]
    fn test_serialization_into_common_interaction_data_structure() {
        let data = BLEOpenID4VPInteractionData {
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
            identity_request_nonce: None,
            openid_request: AuthorizationRequest {
                client_id: "client_id".to_string(),
                state: None,
                nonce: None,
                response_type: None,
                response_mode: None,
                response_uri: None,
                client_metadata: None,
                redirect_uri: None,
                dcql_query: None,
            },
            presentation_submission: None,
            dcql_query: DcqlQuery {
                credentials: vec![],
                credential_sets: None,
            },
        };

        let serialized = serialize_interaction_data(&data).unwrap();

        deserialize_interaction_data::<OpenID4VPVerifierInteractionContent>(Some(&serialized))
            .unwrap();
    }
}

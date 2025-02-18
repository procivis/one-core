use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::BLEPeer;
use crate::provider::exchange_protocol::openid4vc::model::{
    BleOpenId4VpResponse, OpenID4VPAuthorizationRequestParams, OpenID4VPPresentationDefinition,
};

/// Interaction data used for OpenID4VP over BLE
/// used on both holder and verifier side
#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct BLEOpenID4VPInteractionData {
    pub client_id: String,
    pub nonce: String,
    pub task_id: Uuid,
    pub peer: BLEPeer,
    pub identity_request_nonce: Option<String>,
    pub openid_request: OpenID4VPAuthorizationRequestParams,
    pub presentation_submission: Option<BleOpenId4VpResponse>,
    pub presentation_definition: OpenID4VPPresentationDefinition,
}

#[cfg(test)]
mod tests {
    use secrecy::SecretSlice;

    use super::*;
    use crate::provider::bluetooth_low_energy::low_level::dto::DeviceInfo;
    use crate::provider::exchange_protocol::openid4vc::model::OpenID4VPVerifierInteractionContent;
    use crate::provider::exchange_protocol::openid4vc::peer_encryption::PeerEncryption;
    use crate::provider::exchange_protocol::{
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
            openid_request: OpenID4VPAuthorizationRequestParams {
                client_id: "client_id".to_string(),
                client_id_scheme: None,
                state: None,
                nonce: None,
                response_type: None,
                response_mode: None,
                response_uri: None,
                client_metadata: None,
                client_metadata_uri: None,
                presentation_definition: None,
                presentation_definition_uri: None,
                redirect_uri: None,
            },
            presentation_submission: None,
            presentation_definition: OpenID4VPPresentationDefinition {
                id: Uuid::new_v4(),
                input_descriptors: vec![],
            },
        };

        let serialized = serialize_interaction_data(&data).unwrap();

        deserialize_interaction_data::<OpenID4VPVerifierInteractionContent>(Some(&serialized))
            .unwrap();
    }
}

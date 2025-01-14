use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::BLEPeer;
use crate::provider::exchange_protocol::openid4vc::model::{
    BleOpenId4VpResponse, OpenID4VPAuthorizationRequestParams, OpenID4VPPresentationDefinition,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BLEOpenID4VPInteractionData {
    pub nonce: String,
    pub task_id: Uuid,
    pub peer: BLEPeer,
    pub identity_request_nonce: Option<String>,
    pub openid_request: OpenID4VPAuthorizationRequestParams,
    pub presentation_submission: Option<BleOpenId4VpResponse>,
    pub presentation_definition: Option<OpenID4VPPresentationDefinition>,
}

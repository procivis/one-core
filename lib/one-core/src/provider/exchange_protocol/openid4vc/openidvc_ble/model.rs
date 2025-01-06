use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::BLEPeer;
use crate::provider::exchange_protocol::openid4vc::model::{
    BleOpenId4VpResponse, OpenID4VPAuthorizationRequest,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BLEOpenID4VPInteractionData {
    pub nonce: String,
    pub task_id: Uuid,
    pub peer: BLEPeer,
    pub identity_request_nonce: Option<String>,
    pub openid_request: OpenID4VPAuthorizationRequest,
    pub presentation_submission: Option<BleOpenId4VpResponse>,
}

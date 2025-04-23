use serde::{Deserialize, Serialize};

use crate::provider::verification_protocol::openid4vp::model::PresentationSubmissionMappingDTO;

#[derive(Clone, Deserialize, Serialize, Debug)]
pub(crate) struct OpenID4VPBleData {
    pub key: String,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct BleOpenId4VpResponse {
    pub vp_token: String,
    pub presentation_submission: PresentationSubmissionMappingDTO,
}

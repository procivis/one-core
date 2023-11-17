use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct OpenID4VPInteractionContent {
    pub nonce: String,
}

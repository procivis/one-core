use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::dto::OpenID4VPPresentationDefinition;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct OpenID4VCIInteractionContent {
    pub pre_authorized_code_used: bool,
    pub access_token: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub access_token_expires_at: Option<OffsetDateTime>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct OpenID4VPInteractionContent {
    pub nonce: String,
    pub presentation_definition: OpenID4VPPresentationDefinition,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct HolderInteractionData {
    pub issuer_url: String,
    pub credential_endpoint: String,
    pub access_token: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub access_token_expires_at: Option<OffsetDateTime>,
}

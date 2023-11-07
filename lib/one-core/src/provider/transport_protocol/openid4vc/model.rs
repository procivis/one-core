use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct InteractionContent {
    pub pre_authorized_code_used: bool,
    pub access_token: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub access_token_expires_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct HolderInteractionData {
    pub issuer_url: String,
    pub credential_endpoint: String,
    pub access_token: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub access_token_expires_at: Option<OffsetDateTime>,
}

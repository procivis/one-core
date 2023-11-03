use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::service::oidc::dto::DurationSeconds;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct InteractionContent {
    pub pre_authorized_code_used: bool,
    pub access_token: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub access_token_expires_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize)]
pub struct HolderInteractionData {
    pub credential_issuer: String,
    pub pre_authorized_code: String,
    pub format: String,
    pub credential_type: Option<Vec<String>>,
    pub token_endpoint: Option<String>,
    pub credential_endpoint: Option<String>,
    pub access_token: Option<String>,
    pub access_token_expires_at: Option<DurationSeconds>,
}

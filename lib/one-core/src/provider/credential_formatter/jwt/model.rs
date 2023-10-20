use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct JWTHeader {
    #[serde(rename = "alg")]
    pub(crate) algorithm: String,

    #[serde(rename = "kid", default, skip_serializing_if = "Option::is_none")]
    pub(crate) key_id: Option<String>,

    #[serde(rename = "typ", default, skip_serializing_if = "Option::is_none")]
    pub(crate) signature_type: Option<String>,
}

impl Default for JWTHeader {
    fn default() -> Self {
        JWTHeader {
            algorithm: "".to_string(),
            key_id: None,
            signature_type: Some("SDJWT".to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JWTPayload<CustomPayload> {
    /// Time the claims were created at
    #[serde(
        rename = "iat",
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::timestamp::option"
    )]
    pub issued_at: Option<OffsetDateTime>,

    /// Time the claims expire at
    #[serde(
        rename = "exp",
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::timestamp::option"
    )]
    pub expires_at: Option<OffsetDateTime>,

    /// Time the claims will be invalid until
    #[serde(
        rename = "nbf",
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::timestamp::option"
    )]
    pub invalid_before: Option<OffsetDateTime>,

    /// Issuer - This can be set to anything application-specific
    #[serde(rename = "iss", default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,

    /// Subject - This can be set to anything application-specific
    #[serde(rename = "sub", default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,

    /// JWT identifier
    #[serde(rename = "jti", default, skip_serializing_if = "Option::is_none")]
    pub jwt_id: Option<String>,

    /// Nonce
    #[serde(rename = "nonce", default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// Custom (application-defined) claims
    #[serde(flatten)]
    pub custom: CustomPayload,
}

pub(super) struct DecomposedToken<Payload> {
    pub header: JWTHeader,
    pub header_json: String,
    pub payload: JWTPayload<Payload>,
    pub payload_json: String,
    pub signature: Vec<u8>,
}

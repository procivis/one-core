use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JWTHeader {
    #[serde(rename = "alg")]
    pub algorithm: String,

    #[serde(rename = "kid", default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    #[serde(rename = "typ", default, skip_serializing_if = "Option::is_none")]
    pub signature_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JWTPayload<CustomPayload> {
    #[serde(
        rename = "iat",
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::timestamp::option"
    )]
    pub issued_at: Option<OffsetDateTime>,

    #[serde(
        rename = "exp",
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::timestamp::option"
    )]
    pub expires_at: Option<OffsetDateTime>,

    #[serde(
        rename = "nbf",
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::timestamp::option"
    )]
    pub invalid_before: Option<OffsetDateTime>,

    #[serde(rename = "iss", default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,

    #[serde(rename = "sub", default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,

    #[serde(rename = "jti", default, skip_serializing_if = "Option::is_none")]
    pub jwt_id: Option<String>,

    #[serde(rename = "nonce", default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    #[serde(flatten)]
    pub custom: CustomPayload,
}

#[derive(Debug)]
pub struct DecomposedToken<Payload> {
    pub header: JWTHeader,
    pub header_json: String,
    pub payload: JWTPayload<Payload>,
    pub payload_json: String,
    pub signature: Vec<u8>,
}

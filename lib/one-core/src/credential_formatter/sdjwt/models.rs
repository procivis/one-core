use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::credential_formatter::VCCredentialSchemaResponse;

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
pub struct JWTPayload<CustomClaims> {
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

    /// Hash algorithm
    /// https://www.iana.org/assignments/named-information/named-information.xhtml
    #[serde(rename = "_sd_alg", default, skip_serializing_if = "Option::is_none")]
    pub hash_alg: Option<String>,

    /// Custom (application-defined) claims
    #[serde(flatten)]
    pub custom: CustomClaims,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VCContent {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub r#type: Vec<String>,
    pub credential_subject: SDCredentialSubject,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VPContent {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub r#type: Vec<String>,
    pub verifiable_credential: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VC {
    pub vc: VCContent,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VP {
    pub vp: VPContent,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Disclosure {
    pub salt: String,
    pub attribute: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SDCredentialSubject {
    #[serde(rename = "_sd")]
    pub claims: Vec<String>,
    pub one_credential_schema: VCCredentialSchemaResponse,
}

pub(super) struct DecomposedToken<Claims> {
    pub header: JWTHeader,
    pub header_json: String,
    pub payload: JWTPayload<Claims>,
    pub payload_json: String,
    pub signature: Vec<u8>,
    pub disclosures_decoded: Vec<String>,
}

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::{serde_as, skip_serializing_none, OneOrMany};
use shared_types::DidValue;
use time::OffsetDateTime;

use crate::provider::credential_formatter::model::{CredentialSchema, CredentialStatus, Issuer};
use crate::provider::credential_formatter::vcdm::{ContextType, JwtVcdmCredential};

#[skip_serializing_none]
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VCContent {
    #[serde(rename = "@context")]
    pub context: Vec<ContextType>,
    pub id: Option<String>,
    pub r#type: Vec<String>,
    pub credential_subject: SDCredentialSubject,
    #[serde(default)]
    #[serde_as(as = "OneOrMany<_>")]
    pub credential_status: Vec<CredentialStatus>,
    pub credential_schema: Option<CredentialSchema>,
    #[serde(default)]
    pub issuer: Option<Issuer>,
    #[serde(with = "time::serde::rfc3339::option")]
    #[serde(default)]
    pub valid_from: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    #[serde(default)]
    pub valid_until: Option<OffsetDateTime>,
}

// TODO: remove the presentation models, since only JWT formatted presentations are used
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VPContent {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub r#type: Vec<String>,
    #[serde(rename = "_sd_jwt")]
    pub verifiable_credential: Vec<String>,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VcClaim {
    #[serde(rename = "_sd", default, skip_serializing_if = "Vec::is_empty")]
    pub digests: Vec<String>,

    pub vc: JwtVcdmCredential,
    /// Hash algorithm
    /// https://www.iana.org/assignments/named-information/named-information.xhtml
    #[serde(rename = "_sd_alg", default)]
    pub hash_alg: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Sdvp {
    pub vp: VPContent,
    pub nonce: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Disclosure {
    pub salt: String,
    pub key: String,
    pub value: serde_json::Value,
    pub disclosure_array: String,
    pub disclosure: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SDCredentialSubject {
    #[serde(rename = "_sd", default, skip_serializing_if = "Vec::is_empty")]
    pub digests: Vec<String>,
    #[serde(flatten)]
    pub public_claims: HashMap<String, Value>,
}

pub struct DecomposedToken<'a> {
    pub jwt: &'a str,
    pub disclosures: Vec<Disclosure>,
}

pub struct SdJwtFormattingInputs {
    pub holder_did: Option<DidValue>,
    pub holder_key_id: Option<String>,
    pub leeway: u64,
    pub token_type: String,
    pub vc_type: Option<String>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct KeyBindingPayload {
    pub nonce: String,
    pub sd_hash: String,
}

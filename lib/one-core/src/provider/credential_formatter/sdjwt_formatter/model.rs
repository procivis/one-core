use serde::{Deserialize, Serialize};
use serde_with::{serde_as, OneOrMany};
use time::OffsetDateTime;

use crate::provider::credential_formatter::json_ld::model::ContextType;
use crate::provider::credential_formatter::model::{CredentialSchema, CredentialStatus, Issuer};

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VCContent {
    #[serde(rename = "@context")]
    pub context: Vec<ContextType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub r#type: Vec<String>,
    pub credential_subject: SDCredentialSubject,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[serde_as(as = "OneOrMany<_>")]
    pub credential_status: Vec<CredentialStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_schema: Option<CredentialSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<Issuer>,
    #[serde(with = "time::serde::rfc3339::option")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Sdvc {
    pub vc: VCContent,
    /// Hash algorithm
    /// https://www.iana.org/assignments/named-information/named-information.xhtml
    #[serde(rename = "_sd_alg", default, skip_serializing_if = "Option::is_none")]
    pub hash_alg: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Sdvp {
    pub vp: VPContent,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct Disclosure {
    pub salt: String,
    pub key: String,
    pub value: serde_json::Value,
    pub original_disclosure: String,
    pub base64_encoded_disclosure: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SDCredentialSubject {
    #[serde(rename = "_sd")]
    pub claims: Vec<String>,
}

pub struct DecomposedToken<'a> {
    pub jwt: &'a str,
    pub deserialized_disclosures: Vec<Disclosure>,
}

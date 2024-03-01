use serde::{Deserialize, Serialize};

use crate::provider::credential_formatter::CredentialStatus;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VCContent {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub r#type: Vec<String>,
    pub credential_subject: SDCredentialSubject,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<CredentialStatus>,
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

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Disclosure {
    pub salt: String,
    pub key: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SDCredentialSubject {
    #[serde(rename = "_sd")]
    pub claims: Vec<String>,
}

pub(super) struct DecomposedToken<'a> {
    pub jwt: &'a str,
    pub deserialized_disclosures: Vec<(Disclosure, String, String)>,
}

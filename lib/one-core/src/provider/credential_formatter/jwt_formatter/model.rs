use serde::{Deserialize, Serialize};
use serde_with::{serde_as, OneOrMany};
use time::OffsetDateTime;

use crate::provider::credential_formatter::json_ld::model::ContextType;
use crate::provider::credential_formatter::model::{
    CredentialSchema, CredentialStatus, CredentialSubject, Issuer,
};

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VCContent {
    #[serde(rename = "@context")]
    pub context: Vec<ContextType>,
    pub r#type: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub credential_subject: CredentialSubject,
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VPContent {
    #[serde(rename = "@context")]
    pub context: Vec<ContextType>,
    #[serde(rename = "type")]
    pub r#type: Vec<String>,
    pub verifiable_credential: Vec<VerifiableCredential>,
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
    pub nonce: Option<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VerifiableCredential {
    Enveloped(EnvelopedContent),
    Token(String),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct EnvelopedContent {
    #[serde(rename = "@context")]
    pub context: Vec<ContextType>,
    pub id: String,
    #[serde(rename = "type")]
    pub r#type: Vec<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct TokenStatusListContent {
    pub status_list: TokenStatusListSubject,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct TokenStatusListSubject {
    pub bits: usize,
    #[serde(rename = "lst")]
    pub value: String,
}

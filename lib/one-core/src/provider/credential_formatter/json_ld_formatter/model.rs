use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use shared_types::DidValue;
use time::OffsetDateTime;

// #[derive(Debug, Serialize, Deserialize)]
// The main credential
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LdCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    pub r#type: Vec<String>,
    pub issuer: DidValue,
    #[serde(with = "time::serde::rfc3339")]
    pub issuance_date: OffsetDateTime,
    pub credential_subject: LdCredentialSubject,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<LdProof>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LdCredentialSubject {
    pub id: DidValue,
    #[serde(flatten)]
    pub subject: HashMap<String, Claims>,
}

pub type Claims = HashMap<String, String>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LdProof {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub r#type: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created: OffsetDateTime,
    pub cryptosuite: String,
    pub verification_method: String,
    pub proof_purpose: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

// The main presentation
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LdPresentation {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub r#type: String,
    #[serde(with = "time::serde::rfc3339")]
    pub issuance_date: OffsetDateTime,
    pub verifiable_credential: String, // Can be a value, or vector. Decoded later.
    pub holder: DidValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<LdProof>,
}

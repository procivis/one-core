use serde::{Deserialize, Serialize};

use crate::provider::credential_formatter::vcdm::{ContextType, JwtVcdmCredential};

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
pub struct VcClaim {
    pub vc: JwtVcdmCredential,
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

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use time::OffsetDateTime;

#[derive(Debug)]
pub struct DetailCredential {
    pub id: Option<String>,
    pub issued_at: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
    pub invalid_before: Option<OffsetDateTime>,
    pub issuer_did: Option<String>,
    pub subject: Option<String>,
    pub claims: CredentialSubject,
    pub status: Option<CredentialStatus>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VCCredentialClaimSchemaResponse {
    pub key: String,
    pub id: String,
    pub datatype: String,
    pub required: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VCCredentialSchemaResponse {
    pub name: String,
    pub id: String,
    pub claims: Vec<VCCredentialClaimSchemaResponse>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSubject {
    #[serde(flatten)]
    pub values: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Presentation {
    pub id: Option<String>,
    pub issued_at: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
    pub issuer_did: Option<String>,
    pub credentials: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialPresentation {
    pub token: String,
    pub disclosed_keys: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatus {
    pub id: String,
    pub r#type: String,
    pub status_purpose: String,
    #[serde(flatten)]
    pub additional_fields: HashMap<String, String>,
}

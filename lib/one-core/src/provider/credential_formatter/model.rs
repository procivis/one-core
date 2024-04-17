use serde::{Deserialize, Serialize};
use shared_types::DidValue;
use std::collections::HashMap;
use time::OffsetDateTime;

use crate::model::credential_schema::CredentialSchemaType;

#[derive(Debug, Clone)]
pub struct DetailCredential {
    pub id: Option<String>,
    pub issued_at: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
    pub invalid_before: Option<OffsetDateTime>,
    pub issuer_did: Option<DidValue>,
    pub subject: Option<DidValue>,
    pub claims: CredentialSubject,
    pub status: Vec<CredentialStatus>,
    pub credential_schema: Option<CredentialSchema>,
}

impl DetailCredential {
    pub fn is_lvvc(&self) -> bool {
        self.claims.values.contains_key("id") && self.claims.values.contains_key("status")
    }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSubject {
    #[serde(flatten)]
    pub values: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Presentation {
    pub id: Option<String>,
    pub issued_at: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
    pub issuer_did: Option<DidValue>,
    pub nonce: Option<String>,
    pub credentials: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialPresentation {
    pub token: String,
    pub disclosed_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatus {
    pub id: String,
    pub r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_purpose: Option<String>,
    #[serde(flatten)]
    pub additional_fields: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchema {
    // URI
    pub id: String,
    pub r#type: CredentialSchemaType,
}

impl CredentialSchema {
    pub fn new(id: String, r#type: CredentialSchemaType) -> Self {
        Self { id, r#type }
    }
}

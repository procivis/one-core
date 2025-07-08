use indexmap::IndexSet;
use serde::{Deserialize, Serialize};
use serde_with::{OneOrMany, serde_as, skip_serializing_none};

use crate::provider::credential_formatter::model::Issuer;
use crate::provider::credential_formatter::vcdm::{ContextType, VcdmProof};

pub type VerifiableCredential = Vec<serde_json::Map<String, serde_json::Value>>;

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialEnvelope {
    #[serde(rename = "@context")]
    pub context: String,
    pub r#type: String,
    pub id: String,
}

impl CredentialEnvelope {
    pub fn new(format: &str, token: &str) -> Self {
        Self {
            r#type: "EnvelopedVerifiableCredential".to_owned(),
            context: "https://www.w3.org/ns/credentials/v2".to_owned(),
            id: format!("data:application/{format},{token}"),
        }
    }

    // Will return empty string if id is incorrect
    // Could introduce an error here
    pub fn get_token(&self) -> String {
        let res = self.id.split_once(',').unwrap_or(("", ""));
        res.1.to_owned()
    }
}

// The main presentation
#[skip_serializing_none]
#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LdPresentation {
    #[serde(rename = "@context")]
    pub context: IndexSet<ContextType>,

    #[serde_as(as = "OneOrMany<_>")]
    pub r#type: Vec<String>,

    pub verifiable_credential: VerifiableCredential,
    pub holder: Issuer,

    pub proof: Option<VcdmProof>,
}

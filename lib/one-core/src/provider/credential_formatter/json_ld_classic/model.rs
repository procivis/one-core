use serde::{Deserialize, Serialize};

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

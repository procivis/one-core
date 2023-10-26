use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct OpenID4VCICredentialRequestRestDTO {
    pub format: String,
    pub credential_definition: OpenID4VCICredentialDefinition,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OpenID4VCICredentialDefinition {
    pub r#type: Vec<String>,
}

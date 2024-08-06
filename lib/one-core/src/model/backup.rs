use super::credential::Credential;
use super::did::Did;
use one_providers::common_models::key::OpenKey;

#[derive(Debug, Clone)]
pub struct UnexportableEntities {
    pub credentials: Vec<Credential>,
    pub keys: Vec<OpenKey>,
    pub dids: Vec<Did>,
    pub total_credentials: u64,
    pub total_keys: u64,
    pub total_dids: u64,
}

#[derive(Debug, Clone)]
pub struct Metadata {
    pub version: String,
}

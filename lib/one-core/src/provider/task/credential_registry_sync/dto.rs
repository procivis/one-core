use serde::{Deserialize, Serialize};
use shared_types::CredentialId;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRegistrySyncResultDTO {
    pub registered_credentials: Vec<CredentialId>,
}

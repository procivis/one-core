use serde::{Deserialize, Serialize};
use shared_types::CredentialId;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SuspendCheckResultDTO {
    pub updated_credential_ids: Vec<CredentialId>,
    pub total_checks: u64,
}

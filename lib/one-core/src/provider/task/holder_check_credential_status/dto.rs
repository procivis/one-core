use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct HolderCheckCredentialStatusResultDTO {
    pub total_checks: u64,
}

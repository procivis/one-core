use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScanToVerifyCredentialDTO {
    pub schema_id: String,
    pub credential: String,
    pub barcode: String,
}

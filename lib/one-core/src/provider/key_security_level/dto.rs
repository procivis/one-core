use serde::{Deserialize, Serialize};

use crate::model::wallet_unit_attestation::KeyStorageSecurityLevel;

#[derive(Clone, Serialize)]
pub struct KeySecurityLevelCapabilities {
    #[serde(rename = "OPENID_SECURITY_LEVEL")]
    pub openid_security_level: Vec<KeyStorageSecurityLevel>,
}

#[derive(Clone, Default, Deserialize)]
pub struct HolderParams {
    #[serde(default)]
    pub priority: u64,
    #[serde(default)]
    pub key_storages: Vec<String>,
}

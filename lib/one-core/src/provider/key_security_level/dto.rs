use serde::{Deserialize, Serialize};
use standardized_types::openid4vci::SecurityLevel;

#[derive(Clone, Serialize)]
pub struct KeySecurityLevelCapabilities {
    #[serde(rename = "OPENID_SECURITY_LEVEL")]
    pub openid_security_level: Vec<SecurityLevel>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub holder: HolderParams,
}

#[derive(Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HolderParams {
    #[serde(default)]
    pub priority: u64,
    #[serde(default)]
    pub key_storages: Vec<String>,
}

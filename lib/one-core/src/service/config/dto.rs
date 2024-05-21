use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigDTO {
    pub format: HashMap<String, Value>,
    pub exchange: HashMap<String, Value>,
    pub revocation: HashMap<String, Value>,
    pub did: HashMap<String, Value>,
    pub datatype: HashMap<String, Value>,
    pub key_algorithm: HashMap<String, Value>,
    pub key_storage: HashMap<String, Value>,
    pub trust_management: HashMap<String, Value>,
}

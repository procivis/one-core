use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigDTO {
    pub format: HashMap<String, Value>,
    pub identifier: HashMap<String, Value>,
    pub issuance_protocol: HashMap<String, Value>,
    pub verification_protocol: HashMap<String, Value>,
    pub transport: HashMap<String, Value>,
    pub revocation: HashMap<String, Value>,
    pub did: HashMap<String, Value>,
    pub datatype: HashMap<String, Value>,
    pub key_algorithm: HashMap<String, Value>,
    pub key_security_level: HashMap<String, Value>,
    pub key_storage: HashMap<String, Value>,
    pub trust_management: HashMap<String, Value>,
    pub cache_entities: HashMap<String, Value>,
    pub blob_storage: HashMap<String, Value>,
    pub task: HashMap<String, Value>,
    pub wallet_provider: HashMap<String, Value>,
    pub credential_issuer: HashMap<String, Value>,
    pub verification_engagement: HashMap<String, Value>,
}

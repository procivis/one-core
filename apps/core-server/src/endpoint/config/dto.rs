use dto_mapper::From;
use one_core::service::config::dto::ConfigDTO;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use utoipa::ToSchema;

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[schema(example = json!({"format": {}, "exchange": {}, "transport": {}, "revocation": {}, "did": {}, "datatype": {}, "keyAlgorithm": {}, "keyStorage": {}}))]
#[from(ConfigDTO)]
pub struct ConfigRestDTO {
    pub format: HashMap<String, Value>,
    pub exchange: HashMap<String, Value>,
    pub transport: HashMap<String, Value>,
    pub revocation: HashMap<String, Value>,
    pub did: HashMap<String, Value>,
    pub datatype: HashMap<String, Value>,
    pub key_algorithm: HashMap<String, Value>,
    pub key_storage: HashMap<String, Value>,
}

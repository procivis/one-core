use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use utoipa::ToSchema;

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[schema(example = json!({"format": {}, "exchange": {}, "transport": {}, "revocation": {}, "did": {}, "datatype": {}}))]
pub struct ConfigRestDTO {
    pub format: HashMap<String, Value>,
    pub exchange: HashMap<String, Value>,
    pub transport: HashMap<String, Value>,
    pub revocation: HashMap<String, Value>,
    pub did: HashMap<String, Value>,
    pub datatype: HashMap<String, Value>,
}

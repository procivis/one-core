use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[schema(example = json!({"format": {}, "exchange": {}, "did": {}, "datatype": {}}))]
pub struct ConfigDTO {
    pub format: HashMap<String, Value>,
    pub exchange: HashMap<String, Value>,
    pub did: HashMap<String, Value>,
    pub datatype: HashMap<String, Value>,
}

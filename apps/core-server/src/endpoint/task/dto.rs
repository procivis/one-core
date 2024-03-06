use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TaskRequestRestDTO {
    #[schema(example = "SUSPEND_CHECK")]
    pub name: String,
    #[schema(value_type = Option<Object>)]
    pub params: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TaskResponseRestDTO {
    #[serde(flatten)]
    pub result: serde_json::Value,
}

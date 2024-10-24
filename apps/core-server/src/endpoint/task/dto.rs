use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TaskRequestRestDTO {
    /// Identifier of task to be run.
    #[schema(example = "SUSPEND_CHECK")]
    pub name: String,
    /// Parameters to pass to the task.
    #[schema(value_type = Option<Object>)]
    pub params: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TaskResponseRestDTO {
    #[serde(flatten)]
    pub result: serde_json::Value,
}

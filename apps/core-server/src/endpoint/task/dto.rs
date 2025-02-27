use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use utoipa::ToSchema;

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TaskRequestRestDTO {
    /// Choose a task to run. Check the `task` object of the configuration
    /// for supported options and reference the configuration instance.
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

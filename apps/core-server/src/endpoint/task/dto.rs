use proc_macros::{ModifySchema, options_not_nullable};
use serde::{Deserialize, Serialize};
use shared_types::TaskId;
use utoipa::ToSchema;

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, ModifySchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TaskRequestRestDTO {
    /// Name of the task to run, as defined in the `task` configuration
    /// object.
    #[modify_schema(field = task)]
    pub name: TaskId,
    /// Task-specific parameters. Most tasks require no parameters.
    #[schema(value_type = Option<Object>)]
    pub params: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaskResponseRestDTO {
    /// Task execution result. The structure varies by task type.
    #[serde(flatten)]
    pub result: serde_json::Value,
}

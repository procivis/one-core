use serde::Deserialize;
use shared_types::TaskId;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CommonParams {
    pub webhook_task: Option<TaskId>,
}

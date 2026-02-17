use serde_json::Value;
use shared_types::TaskId;

use super::TaskService;
use crate::service::error::{MissingProviderError, ServiceError};

impl TaskService {
    pub async fn run(&self, task_id: &TaskId) -> Result<Value, ServiceError> {
        let task = self
            .task_provider
            .get_task(task_id)
            .ok_or(MissingProviderError::Task(task_id.to_owned()))?;

        let result = task.run().await?;
        tracing::info!("Executed task `{task_id}`");
        Ok(result)
    }
}

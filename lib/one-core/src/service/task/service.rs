use serde_json::Value;

use super::TaskService;
use crate::service::error::{MissingProviderError, ServiceError};

impl TaskService {
    pub async fn run(&self, task_id: &str) -> Result<Value, ServiceError> {
        let task = self
            .task_provider
            .get_task(task_id)
            .ok_or(MissingProviderError::Task(task_id.to_owned()))?;

        task.run().await
    }
}

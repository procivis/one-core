use serde_json::Value;

use crate::service::error::ServiceError;

use super::Task;

#[derive(Default)]
pub struct SuspendCheckProvider {}

#[async_trait::async_trait]
impl Task for SuspendCheckProvider {
    async fn run(&self) -> Result<Value, ServiceError> {
        todo!()
    }
}

impl SuspendCheckProvider {
    pub fn new() -> Self {
        SuspendCheckProvider {}
    }
}

use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

use self::suspend_check::SuspendCheckProvider;

use crate::config::{
    core_config::{TaskConfig, TaskType},
    ConfigError,
};
use crate::service::error::ServiceError;

pub mod provider;
pub mod suspend_check;

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait Task: Send + Sync {
    async fn run(&self) -> Result<Value, ServiceError>;
}

pub fn tasks_from_config(
    config: &TaskConfig,
) -> Result<HashMap<String, Arc<dyn Task>>, ConfigError> {
    let mut providers: HashMap<String, Arc<dyn Task>> = HashMap::new();

    for (name, field) in config.iter() {
        if field.disabled() {
            continue;
        }

        let provider = match &field.r#type {
            TaskType::SuspendCheck => Arc::new(SuspendCheckProvider::new()),
        };
        providers.insert(name.to_owned(), provider);
    }

    Ok(providers)
}

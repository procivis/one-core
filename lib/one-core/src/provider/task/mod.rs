use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

use self::suspend_check::SuspendCheckProvider;

use crate::service::error::ServiceError;
use crate::{
    config::{
        core_config::{TaskConfig, TaskType},
        ConfigError,
    },
    provider::revocation::provider::RevocationMethodProvider,
    repository::{
        credential_repository::CredentialRepository, history_repository::HistoryRepository,
    },
};

pub mod provider;
pub mod suspend_check;

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait Task: Send + Sync {
    async fn run(&self) -> Result<Value, ServiceError>;
}

pub(crate) fn tasks_from_config(
    config: &TaskConfig,
    credential_repository: Arc<dyn CredentialRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
) -> Result<HashMap<String, Arc<dyn Task>>, ConfigError> {
    let mut providers: HashMap<String, Arc<dyn Task>> = HashMap::new();

    for (name, field) in config.iter() {
        if field.disabled() {
            continue;
        }

        let provider = match &field.r#type {
            TaskType::SuspendCheck => Arc::new(SuspendCheckProvider::new(
                credential_repository.to_owned(),
                revocation_method_provider.to_owned(),
                history_repository.to_owned(),
            )),
        };
        providers.insert(name.to_owned(), provider);
    }

    Ok(providers)
}

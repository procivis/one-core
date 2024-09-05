use std::collections::HashMap;
use std::sync::Arc;

use one_providers::key_storage::provider::KeyProvider;
use one_providers::revocation::provider::RevocationMethodProvider;
use serde_json::Value;

use self::suspend_check::SuspendCheckProvider;
use crate::config::core_config::{TaskConfig, TaskType};
use crate::config::ConfigError;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::service::error::ServiceError;

pub mod provider;
pub mod suspend_check;

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait Task: Send + Sync {
    async fn run(&self) -> Result<Value, ServiceError>;
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn tasks_from_config(
    config: &TaskConfig,
    credential_repository: Arc<dyn CredentialRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
    validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
    key_provider: Arc<dyn KeyProvider>,
    core_base_url: Option<String>,
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
                revocation_list_repository.to_owned(),
                validity_credential_repository.to_owned(),
                key_provider.to_owned(),
                core_base_url.to_owned(),
            )),
        };
        providers.insert(name.to_owned(), provider);
    }

    Ok(providers)
}

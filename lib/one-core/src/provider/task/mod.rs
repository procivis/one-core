use std::collections::HashMap;
use std::sync::Arc;

use retain_proof_check::RetainProofCheck;
use serde_json::Value;

use self::suspend_check::SuspendCheckProvider;
use super::credential_formatter::provider::CredentialFormatterProvider;
use super::did_method::provider::DidMethodProvider;
use super::key_algorithm::provider::KeyAlgorithmProvider;
use crate::config::core_config::{TaskConfig, TaskType};
use crate::config::ConfigError;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::claim_repository::ClaimRepository;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::service::error::ServiceError;

pub mod provider;
pub mod retain_proof_check;
pub mod suspend_check;

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait Task: Send + Sync {
    async fn run(&self) -> Result<Value, ServiceError>;
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn tasks_from_config(
    config: &TaskConfig,
    claim_repository: Arc<dyn ClaimRepository>,
    credential_repository: Arc<dyn CredentialRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
    validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    proof_repository: Arc<dyn ProofRepository>,
    core_base_url: Option<String>,
) -> Result<HashMap<String, Arc<dyn Task>>, ConfigError> {
    let mut providers: HashMap<String, Arc<dyn Task>> = HashMap::new();

    for (name, field) in config.iter() {
        if !field.enabled() {
            continue;
        }

        let provider = match &field.r#type {
            TaskType::SuspendCheck => Arc::new(SuspendCheckProvider::new(
                credential_repository.to_owned(),
                revocation_method_provider.to_owned(),
                revocation_list_repository.to_owned(),
                validity_credential_repository.to_owned(),
                formatter_provider.to_owned(),
                did_method_provider.to_owned(),
                key_provider.to_owned(),
                key_algorithm_provider.to_owned(),
                core_base_url.to_owned(),
            )) as _,
            TaskType::RetainProofCheck => Arc::new(RetainProofCheck::new(
                claim_repository.clone(),
                credential_repository.clone(),
                proof_repository.clone(),
                history_repository.clone(),
            )) as _,
        };
        providers.insert(name.to_owned(), provider);
    }

    Ok(providers)
}

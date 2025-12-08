use std::collections::HashMap;
use std::sync::Arc;

use serde::de::DeserializeOwned;

use super::Task;
use super::certificate_check::CertificateCheck;
use super::holder_check_credential_status::HolderCheckCredentialStatus;
use super::retain_proof_check::RetainProofCheck;
use super::suspend_check::SuspendCheckProvider;
use crate::config::ConfigValidationError;
use crate::config::core_config::{ConfigFields, CoreConfig, Fields, TaskType};
use crate::proto::certificate_validator::CertificateValidator;
use crate::provider::blob_storage_provider::BlobStorageProvider;
use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::claim_repository::ClaimRepository;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::credential::CredentialService;

#[cfg_attr(test, mockall::automock)]
pub trait TaskProvider: Send + Sync {
    fn get_task(&self, task_id: &str) -> Option<Arc<dyn Task>>;
}

struct TaskProviderImpl {
    tasks: HashMap<String, Arc<dyn Task>>,
}

impl TaskProviderImpl {
    fn new(tasks: HashMap<String, Arc<dyn Task>>) -> Self {
        Self { tasks }
    }
}

impl TaskProvider for TaskProviderImpl {
    fn get_task(&self, task_id: &str) -> Option<Arc<dyn Task>> {
        self.tasks.get(task_id).cloned()
    }
}

#[expect(clippy::too_many_arguments)]
pub(crate) fn task_provider_from_config(
    config: &CoreConfig,
    claim_repository: Arc<dyn ClaimRepository>,
    credential_repository: Arc<dyn CredentialRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    certificate_repository: Arc<dyn CertificateRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    credential_service: CredentialService,
    certificate_validator: Arc<dyn CertificateValidator>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
) -> Result<Arc<dyn TaskProvider>, ConfigValidationError> {
    let mut providers: HashMap<String, Arc<dyn Task>> = HashMap::new();

    for (name, field) in config.task.iter() {
        if !field.enabled() {
            continue;
        }

        let provider = match &field.r#type {
            TaskType::SuspendCheck => Arc::new(SuspendCheckProvider::new(
                credential_repository.clone(),
                credential_service.clone(),
            )) as _,
            TaskType::RetainProofCheck => Arc::new(RetainProofCheck::new(
                claim_repository.clone(),
                credential_repository.clone(),
                proof_repository.clone(),
                history_repository.clone(),
                blob_storage_provider.clone(),
            )) as _,
            TaskType::CertificateCheck => Arc::new(CertificateCheck::new(
                certificate_repository.clone(),
                identifier_repository.clone(),
                certificate_validator.clone(),
            )) as _,
            TaskType::HolderCheckCredentialStatus => Arc::new(HolderCheckCredentialStatus::new(
                parse_params(field)?,
                credential_repository.clone(),
                credential_service.clone(),
            )) as _,
        };
        providers.insert(name.to_owned(), provider);
    }

    Ok(Arc::new(TaskProviderImpl::new(providers)))
}

fn parse_params<P: DeserializeOwned>(
    field: &Fields<TaskType>,
) -> Result<Option<P>, ConfigValidationError> {
    field
        .params
        .as_ref()
        .and_then(|p| p.merge())
        .map(|v| serde_json::from_value::<P>(v))
        .transpose()
        .map_err(|source| ConfigValidationError::FieldsDeserialization {
            source,
            key: "task".to_string(),
        })
}

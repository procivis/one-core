use std::collections::HashMap;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use shared_types::TaskId;

use super::Task;
use super::certificate_check::CertificateCheck;
use super::holder_check_credential_status::HolderCheckCredentialStatus;
use super::interaction_expiration_check::InteractionExpirationCheckProvider;
use super::retain_proof_check::RetainProofCheck;
use super::suspend_check::SuspendCheckProvider;
use super::webhook_notify::WebhookNotify;
use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, Fields, TaskType};
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::credential_validity_manager::CredentialValidityManager;
use crate::proto::notification_sender::NotificationSender;
use crate::proto::session_provider::SessionProvider;
use crate::provider::blob_storage_provider::BlobStorageProvider;
use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::claim_repository::ClaimRepository;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::notification_repository::NotificationRepository;
use crate::repository::proof_repository::ProofRepository;

#[cfg_attr(test, mockall::automock)]
pub trait TaskProvider: Send + Sync {
    fn get_task(&self, task_id: &TaskId) -> Option<Arc<dyn Task>>;
}

struct TaskProviderImpl {
    tasks: HashMap<TaskId, Arc<dyn Task>>,
}

impl TaskProvider for TaskProviderImpl {
    fn get_task(&self, task_id: &TaskId) -> Option<Arc<dyn Task>> {
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
    interaction_repository: Arc<dyn InteractionRepository>,
    notification_repository: Arc<dyn NotificationRepository>,
    credential_validity_manager: Arc<dyn CredentialValidityManager>,
    certificate_validator: Arc<dyn CertificateValidator>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
    session_provider: Arc<dyn SessionProvider>,
    notification_sender: Arc<dyn NotificationSender>,
) -> Result<Arc<dyn TaskProvider>, ConfigValidationError> {
    let mut tasks: HashMap<TaskId, Arc<dyn Task>> = HashMap::new();

    for (name, field) in config.task.iter() {
        if !field.enabled {
            continue;
        }

        let task: Arc<dyn Task> = match &field.r#type {
            TaskType::SuspendCheck => Arc::new(SuspendCheckProvider::new(
                credential_repository.clone(),
                credential_validity_manager.clone(),
            )),
            TaskType::RetainProofCheck => Arc::new(RetainProofCheck::new(
                claim_repository.clone(),
                credential_repository.clone(),
                proof_repository.clone(),
                history_repository.clone(),
                blob_storage_provider.clone(),
            )),
            TaskType::CertificateCheck => Arc::new(CertificateCheck::new(
                certificate_repository.clone(),
                identifier_repository.clone(),
                certificate_validator.clone(),
            )),
            TaskType::HolderCheckCredentialStatus => Arc::new(HolderCheckCredentialStatus::new(
                parse_params(field)?,
                credential_repository.clone(),
                credential_validity_manager.clone(),
            )),
            TaskType::InteractionExpirationCheck => {
                Arc::new(InteractionExpirationCheckProvider::new(
                    interaction_repository.clone(),
                    history_repository.clone(),
                    credential_repository.clone(),
                    proof_repository.clone(),
                    session_provider.clone(),
                ))
            }
            TaskType::WebhookNotify => {
                let params = field.deserialize().map_err(|source| {
                    ConfigValidationError::FieldsDeserialization {
                        key: name.to_string(),
                        source,
                    }
                })?;

                Arc::new(WebhookNotify::new(
                    name.to_owned(),
                    params,
                    notification_repository.clone(),
                    notification_sender.clone(),
                ))
            }
        };
        tasks.insert(name.to_owned(), task);
    }

    Ok(Arc::new(TaskProviderImpl { tasks }))
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

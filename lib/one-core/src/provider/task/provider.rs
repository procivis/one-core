use std::collections::HashMap;
use std::sync::Arc;

use shared_types::TaskId;
use thiserror::Error;

use super::Task;
use super::certificate_check::CertificateCheck;
use super::holder_check_credential_status::HolderCheckCredentialStatus;
use super::interaction_expiration_check::InteractionExpirationCheckProvider;
use super::lifecycle_check::LifecycleCheckProvider;
use super::retain_proof_check::RetainProofCheck;
use super::trust_list_subscription_update::TrustListSubscriptionUpdateTask;
use super::webhook_notify::WebhookNotify;
use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, TaskType};
use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::credential_validity_manager::CredentialValidityManager;
use crate::proto::ecosystem_sync::EcosystemSync;
use crate::proto::native_credential_manager::NativeCredentialManager;
use crate::proto::notification_sender::NotificationSender;
use crate::proto::session_provider::SessionProvider;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::ecosystem::directory::EcosystemDirectory;
use crate::provider::task::credential_registry_sync::CredentialRegistrySync;
use crate::provider::task::ecosystem_lifecycle_check::EcosystemLifecycleCheckTask;
use crate::provider::task::ecosystem_sync::EcosystemSyncTask;
use crate::provider::trust_list_subscriber::provider::TrustListSubscriberProvider;
use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::claim_repository::ClaimRepository;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::instance_repository::InstanceRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::notification_repository::NotificationRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::repository::trust_list_subscription_repository::TrustListSubscriptionRepository;

#[derive(Debug, Error)]
pub enum TaskProviderError {
    #[error("Cannot find task `{0}`")]
    NotFound(TaskId),
}

impl ErrorCodeMixin for TaskProviderError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::NotFound(_) => ErrorCode::BR_0103,
        }
    }
}

#[cfg_attr(test, mockall::automock)]
pub trait TaskProvider: Send + Sync {
    fn get_task(&self, task_id: &TaskId) -> Result<Arc<dyn Task>, TaskProviderError>;
}

struct TaskProviderImpl {
    tasks: HashMap<TaskId, Arc<dyn Task>>,
}

impl TaskProvider for TaskProviderImpl {
    fn get_task(&self, task_id: &TaskId) -> Result<Arc<dyn Task>, TaskProviderError> {
        self.tasks
            .get(task_id)
            .cloned()
            .ok_or_else(|| TaskProviderError::NotFound(task_id.to_owned()))
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
    trust_list_subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
    holder_wallet_unit_repository: Arc<dyn InstanceRepository>,
    credential_validity_manager: Arc<dyn CredentialValidityManager>,
    certificate_validator: Arc<dyn CertificateValidator>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
    session_provider: Arc<dyn SessionProvider>,
    notification_sender: Arc<dyn NotificationSender>,
    trust_list_subscription_provider: Arc<dyn TrustListSubscriberProvider>,
    ecosystem_sync: Arc<dyn EcosystemSync>,
    ecosystem_directory: Arc<dyn EcosystemDirectory>,
    native_credential_manager: Option<Arc<dyn NativeCredentialManager>>,
) -> Result<Arc<dyn TaskProvider>, ConfigValidationError> {
    let config_clone = Arc::new(config.clone());
    let mut tasks: HashMap<TaskId, Arc<dyn Task>> = HashMap::new();
    for (name, field) in config.task.iter() {
        if !field.enabled {
            continue;
        }

        let task: Arc<dyn Task> = match &field.r#type {
            TaskType::LifecycleCheck => Arc::new(LifecycleCheckProvider::new(
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
            TaskType::TrustListSubscriptionUpdate => {
                Arc::new(TrustListSubscriptionUpdateTask::new(
                    trust_list_subscription_provider.clone(),
                    trust_list_subscription_repository.clone(),
                    history_repository.clone(),
                    session_provider.clone(),
                ))
            }
            TaskType::EcosystemSync => Arc::new(EcosystemSyncTask::new(
                holder_wallet_unit_repository.clone(),
                ecosystem_sync.clone(),
            )),
            TaskType::EcosystemLifecycleCheck => Arc::new(EcosystemLifecycleCheckTask::new(
                ecosystem_directory.clone(),
            )),
            TaskType::CredentialRegistrySync => Arc::new(CredentialRegistrySync::new(
                config_clone.clone(),
                credential_repository.clone(),
                native_credential_manager.clone(),
            )),
        };
        tasks.insert(name.to_owned(), task);
    }

    Ok(Arc::new(TaskProviderImpl { tasks }))
}

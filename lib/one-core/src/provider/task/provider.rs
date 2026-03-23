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
use super::trust_list_subscription_update::TrustListSubscriptionUpdateTask;
use super::webhook_notify::WebhookNotify;
use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, Fields, TaskType};
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::credential_validity_manager::CredentialValidityManager;
use crate::proto::notification_sender::NotificationSender;
use crate::proto::session_provider::SessionProvider;
use crate::proto::trust_collection::TrustCollectionManager;
use crate::proto::trust_list_subscription_sync::TrustListSubscriptionSync;
use crate::provider::blob_storage_provider::BlobStorageProvider;
use crate::provider::task::trust_collection_sync::TrustCollectionSyncTask;
use crate::provider::trust_list_subscriber::provider::TrustListSubscriberProvider;
use crate::provider::wallet_provider_client::WalletProviderClient;
use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::claim_repository::ClaimRepository;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::holder_wallet_unit_repository::HolderWalletUnitRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::notification_repository::NotificationRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::repository::trust_collection_repository::TrustCollectionRepository;
use crate::repository::trust_list_subscription_repository::TrustListSubscriptionRepository;

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
    trust_list_subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
    holder_wallet_unit_repository: Arc<dyn HolderWalletUnitRepository>,
    trust_collection_repository: Arc<dyn TrustCollectionRepository>,
    credential_validity_manager: Arc<dyn CredentialValidityManager>,
    certificate_validator: Arc<dyn CertificateValidator>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
    session_provider: Arc<dyn SessionProvider>,
    notification_sender: Arc<dyn NotificationSender>,
    trust_list_subscription_provider: Arc<dyn TrustListSubscriberProvider>,
    collection_sync: Arc<dyn TrustCollectionManager>,
    subscription_sync: Arc<dyn TrustListSubscriptionSync>,
    wallet_unit_client: Arc<dyn WalletProviderClient>,
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
            TaskType::TrustListSubscriptionUpdate => {
                Arc::new(TrustListSubscriptionUpdateTask::new(
                    trust_list_subscription_provider.clone(),
                    trust_list_subscription_repository.clone(),
                    history_repository.clone(),
                    session_provider.clone(),
                ))
            }
            TaskType::TrustCollectionSync => Arc::new(TrustCollectionSyncTask::new(
                holder_wallet_unit_repository.clone(),
                wallet_unit_client.clone(),
                collection_sync.clone(),
                trust_collection_repository.clone(),
                subscription_sync.clone(),
            )),
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

use std::collections::HashMap;
use std::sync::Arc;

use certificate_check::CertificateCheck;
use retain_proof_check::RetainProofCheck;
use serde::de::DeserializeOwned;
use serde_json::Value;

use self::suspend_check::SuspendCheckProvider;
use crate::config::core_config::{Fields, TaskConfig, TaskType};
use crate::config::{ConfigError, ConfigParsingError};
use crate::provider::blob_storage_provider::BlobStorageProvider;
use crate::provider::task::holder_check_credential_status::HolderCheckCredentialStatus;
use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::claim_repository::ClaimRepository;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::certificate::validator::CertificateValidator;
use crate::service::credential::CredentialService;
use crate::service::error::ServiceError;

pub mod certificate_check;
pub mod holder_check_credential_status;
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
    proof_repository: Arc<dyn ProofRepository>,
    certificate_repository: Arc<dyn CertificateRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    credential_service: CredentialService,
    certificate_validator: Arc<dyn CertificateValidator>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
) -> Result<HashMap<String, Arc<dyn Task>>, ConfigError> {
    let mut providers: HashMap<String, Arc<dyn Task>> = HashMap::new();

    for (name, field) in config.iter() {
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

    Ok(providers)
}

fn parse_params<P: DeserializeOwned>(field: &Fields<TaskType>) -> Result<Option<P>, ConfigError> {
    field
        .params
        .as_ref()
        .and_then(|p| p.merge())
        .map(|v| serde_json::from_value::<P>(v))
        .transpose()
        .map_err(|e| ConfigError::Parsing(ConfigParsingError::GeneralParsingError(e.to_string())))
}

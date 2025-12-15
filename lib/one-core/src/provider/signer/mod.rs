pub mod dto;
pub mod model;
pub mod provider;
pub mod registration_certificate;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::json;
use uuid::Uuid;

use crate::config::ConfigValidationError;
use crate::config::core_config::{SignerConfig, SignerType};
use crate::proto::clock::Clock;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::service::error::ServiceError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait Signer: Send + Sync {
    fn get_capabilities(&self) -> model::SignerCapabilities;

    async fn sign(
        &self,
        request: dto::CreateSignatureRequestDTO,
    ) -> Result<dto::CreateSignatureResponseDTO, ServiceError>;

    async fn revoke(&self, id: Uuid) -> Result<(), ServiceError>;
}

pub(crate) fn signers_from_config(
    config: &mut SignerConfig,
    clock: Arc<dyn Clock>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    history_repository: Arc<dyn HistoryRepository>,
) -> Result<HashMap<String, Arc<dyn Signer>>, ConfigValidationError> {
    let mut levels: HashMap<String, Arc<dyn Signer>> = HashMap::new();

    for (name, fields) in config.iter_mut() {
        if !fields.enabled.unwrap_or_default() {
            continue;
        }

        let signer: Arc<dyn Signer> = match fields.r#type {
            SignerType::RegistrationCertificate => {
                let params = registration_certificate::Params::try_from(fields.params.as_ref())
                    .map_err(|e| ConfigValidationError::FieldsDeserialization {
                        key: name.to_owned(),
                        source: e,
                    })?;
                let revocation = match params.revocation_method.as_deref() {
                    Some(method) => {
                        match revocation_method_provider.get_revocation_method(method) {
                            Some(value) => Ok(Some(value)),
                            None => Err(ConfigValidationError::EntryNotFound(format!(
                                "No revocation method of type {}",
                                method
                            ))),
                        }
                    }
                    None => Ok(None),
                }?;

                Arc::new(registration_certificate::RegistrationCertificate::new(
                    params,
                    clock.clone(),
                    revocation,
                    key_provider.clone(),
                    key_algorithm_provider.clone(),
                    identifier_repository.clone(),
                    history_repository.clone(),
                ))
            }
        };
        fields.capabilities = Some(json!(signer.get_capabilities()));

        levels.insert(name.to_owned(), signer);
    }
    Ok(levels)
}

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::json;
use uuid::Uuid;

use super::{Signer, registration_certificate};
use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, SignerType};
use crate::model::revocation_list::RevocationListEntityInfo;
use crate::proto::clock::Clock;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::service::error::{EntityNotFoundError, MissingProviderError, ServiceError};

#[async_trait]
pub(crate) trait SignerProvider: Send + Sync {
    async fn get_for_signature_id(&self, id: Uuid) -> Result<Arc<dyn Signer>, ServiceError>;

    fn get_from_type(&self, r#type: &str) -> Option<Arc<dyn Signer>>;
}

struct SignerProviderImpl {
    signers: HashMap<String, Arc<dyn Signer>>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
}

#[async_trait]
impl SignerProvider for SignerProviderImpl {
    async fn get_for_signature_id(&self, id: Uuid) -> Result<Arc<dyn Signer>, ServiceError> {
        let entry = self
            .revocation_list_repository
            .get_entry_by_id(id.into())
            .await?
            .ok_or(ServiceError::EntityNotFound(
                EntityNotFoundError::RevocationListEntry(id.into()),
            ))?;

        match entry.entity_info {
            RevocationListEntityInfo::Signature(sig_type) => self
                .get_from_type(sig_type.as_str())
                .ok_or(ServiceError::MissingProvider(MissingProviderError::Signer(
                    sig_type,
                ))),
            _ => Err(ServiceError::MappingError(
                "Invalid revocation list entry type".to_string(),
            )),
        }
    }

    fn get_from_type(&self, r#type: &str) -> Option<Arc<dyn Signer>> {
        self.signers.get(r#type).cloned()
    }
}

#[expect(clippy::too_many_arguments)]
pub(crate) fn signer_provider_from_config(
    config: &mut CoreConfig,
    clock: Arc<dyn Clock>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
) -> Result<Arc<dyn SignerProvider>, ConfigValidationError> {
    let mut signers: HashMap<String, Arc<dyn Signer>> = HashMap::new();

    for (name, fields) in config.signer.iter_mut() {
        if !fields.enabled {
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

        signers.insert(name.to_owned(), signer);
    }

    Ok(Arc::new(SignerProviderImpl {
        signers,
        revocation_list_repository,
    }))
}

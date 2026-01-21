use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::json;
use uuid::Uuid;

use super::{Signer, registration_certificate};
use crate::config::core_config::{ConfigExt, CoreConfig, SignerType};
use crate::config::{ConfigValidationError, ProviderReference};
use crate::model::revocation_list::RevocationListEntityInfo;
use crate::proto::clock::Clock;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::service::error::{EntityNotFoundError, MissingProviderError, ServiceError};

#[async_trait]
pub(crate) trait SignerProvider: Send + Sync {
    async fn get_for_signature_id(
        &self,
        id: Uuid,
    ) -> Result<(String, Arc<dyn Signer>), ServiceError>;

    fn get(&self, name: &str) -> Option<Arc<dyn Signer>>;
}

struct SignerProviderImpl {
    signers: HashMap<String, Arc<dyn Signer>>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
}

#[async_trait]
impl SignerProvider for SignerProviderImpl {
    async fn get_for_signature_id(
        &self,
        id: Uuid,
    ) -> Result<(String, Arc<dyn Signer>), ServiceError> {
        let entry = self
            .revocation_list_repository
            .get_entry_by_id(id.into())
            .await?
            .ok_or(ServiceError::EntityNotFound(
                EntityNotFoundError::RevocationListEntry(id.into()),
            ))?;

        match entry.entity_info {
            RevocationListEntityInfo::Signature(name, _) => {
                let signer = self.get(&name).ok_or(ServiceError::MissingProvider(
                    MissingProviderError::Signer(name.clone()),
                ))?;
                Ok((name, signer))
            }
            _ => Err(ServiceError::MappingError(
                "Invalid revocation list entry type".to_string(),
            )),
        }
    }

    fn get(&self, name: &str) -> Option<Arc<dyn Signer>> {
        self.signers.get(name).cloned()
    }
}

pub(crate) fn signer_provider_from_config(
    config: &mut CoreConfig,
    clock: Arc<dyn Clock>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
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
                let signer = registration_certificate::RegistrationCertificate::new(
                    params.clone(),
                    clock.clone(),
                    revocation_method_provider.clone(),
                    key_provider.clone(),
                    key_algorithm_provider.clone(),
                );

                if let Some(revocation_method) = &params.revocation_method {
                    let revocation_type =
                        config.revocation.get_if_enabled(revocation_method)?.r#type;
                    let compatible_revocation_types = signer.get_capabilities().revocation_methods;
                    if !compatible_revocation_types.contains(&revocation_type) {
                        return Err(ConfigValidationError::incompatible_provider_ref(
                            name.to_owned(),
                            ProviderReference::RevocationMethod(revocation_method.to_owned()),
                            &compatible_revocation_types,
                        ));
                    }
                }
                Arc::new(signer)
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

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::json;
use shared_types::RevocationMethodId;
use uuid::Uuid;

use super::{Signer, access_certificate, registration_certificate, x509_certificate};
use crate::config::core_config::{ConfigExt, CoreConfig, RevocationConfig, SignerType};
use crate::config::{ConfigValidationError, ProviderReference};
use crate::error::ContextWithErrorCode;
use crate::model::revocation_list::RevocationListEntityInfo;
use crate::proto::clock::Clock;
use crate::proto::session_provider::SessionProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::service::error::{EntityNotFoundError, MissingProviderError, ServiceError};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
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
            .await
            .error_while("getting revocation list entry")?
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

#[allow(clippy::too_many_arguments)]
pub(crate) fn signer_provider_from_config(
    core_base_url: Option<String>,
    config: &mut CoreConfig,
    clock: Arc<dyn Clock>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
    session_provider: Arc<dyn SessionProvider>,
) -> Result<Arc<dyn SignerProvider>, ConfigValidationError> {
    let mut signers: HashMap<String, Arc<dyn Signer>> = HashMap::new();
    let revocation_config = &config.revocation;

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
                    name.to_owned(),
                    params.clone(),
                    clock.clone(),
                    revocation_method_provider.clone(),
                    key_provider.clone(),
                    key_algorithm_provider.clone(),
                    session_provider.clone(),
                );

                if let Some(revocation_method) = &params.revocation_method {
                    validate_revocation_method_compatibility(
                        name,
                        &signer,
                        revocation_config,
                        revocation_method,
                    )?;
                }
                Arc::new(signer)
            }
            SignerType::AccessCertificate => {
                let params: access_certificate::Params = fields.deserialize().map_err(|e| {
                    ConfigValidationError::FieldsDeserialization {
                        key: name.to_owned(),
                        source: e,
                    }
                })?;
                let signer = access_certificate::AccessCertificateSigner::new(
                    name.to_owned(),
                    params.clone(),
                    key_provider.clone(),
                    revocation_method_provider.clone(),
                    session_provider.clone(),
                    core_base_url
                        .clone()
                        .ok_or(ConfigValidationError::MissingBaseUrl)?,
                );

                if let Some(revocation_method) = &params.revocation_method {
                    validate_revocation_method_compatibility(
                        name,
                        &signer,
                        revocation_config,
                        revocation_method,
                    )?;
                }
                Arc::new(signer)
            }
            SignerType::X509Certificate => {
                let params: x509_certificate::Params = fields.deserialize().map_err(|e| {
                    ConfigValidationError::FieldsDeserialization {
                        key: name.to_owned(),
                        source: e,
                    }
                })?;
                let signer = x509_certificate::X509CertificateSigner::new(
                    name.to_owned(),
                    params.clone(),
                    key_provider.clone(),
                    revocation_method_provider.clone(),
                    session_provider.clone(),
                );

                if let Some(revocation_method) = &params.revocation_method {
                    validate_revocation_method_compatibility(
                        name,
                        &signer,
                        revocation_config,
                        revocation_method,
                    )?;
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

fn validate_revocation_method_compatibility(
    name: &String,
    signer: &dyn Signer,
    revocation_config: &RevocationConfig,
    revocation_method: &RevocationMethodId,
) -> Result<(), ConfigValidationError> {
    let revocation_type = revocation_config.get_if_enabled(revocation_method)?.r#type;
    let compatible_revocation_types = signer.get_capabilities().revocation_methods;
    if !compatible_revocation_types.contains(&revocation_type) {
        return Err(ConfigValidationError::incompatible_provider_ref(
            name.to_owned(),
            ProviderReference::RevocationMethod(revocation_method.to_owned()),
            &compatible_revocation_types,
        ));
    }
    Ok(())
}

use std::collections::HashMap;
use std::sync::Arc;

use serde::Serialize;

use crate::config::core_config::{KeyStorageConfig, KeyStorageType};
use crate::config::{ConfigError, ConfigParsingError, ConfigValidationError};
use crate::crypto::{signer::error::SignerError, CryptoProvider};
use crate::model::key::{Key, KeyId};
use crate::provider::key_storage::azure_vault::AzureVaultKeyProvider;
use crate::provider::key_storage::pkcs11::PKCS11KeyProvider;
use crate::{provider::key_storage::internal::InternalKeyProvider, service::error::ServiceError};

use self::secure_element::{NativeKeyStorage, SecureElementKeyProvider};
use super::key_algorithm::provider::KeyAlgorithmProvider;

pub mod azure_vault;
pub mod internal;
pub mod pkcs11;
pub mod provider;
pub mod secure_element;

#[derive(Clone, Default, Serialize)]
pub struct KeyStorageCapabilities {
    pub algorithms: Vec<String>,
    pub security: Vec<String>,
}

pub struct GeneratedKey {
    pub public_key: Vec<u8>,
    pub key_reference: Vec<u8>,
}

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait KeyStorage: Send + Sync {
    async fn generate(&self, key_id: &KeyId, key_type: &str) -> Result<GeneratedKey, ServiceError>;
    async fn sign(&self, key: &Key, message: &[u8]) -> Result<Vec<u8>, SignerError>;
    fn get_capabilities(&self) -> KeyStorageCapabilities;
}

pub fn key_providers_from_config(
    config: &mut KeyStorageConfig,
    crypto: Arc<dyn CryptoProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    secure_element_key_storage: Option<Arc<dyn NativeKeyStorage>>,
) -> Result<HashMap<String, Arc<dyn KeyStorage>>, ConfigError> {
    let mut providers: HashMap<String, Arc<dyn KeyStorage>> = HashMap::new();

    for (name, field) in config.iter() {
        let provider = match &field.r#type {
            KeyStorageType::Internal => {
                let params = config.get(name)?;
                Arc::new(InternalKeyProvider::new(
                    key_algorithm_provider.clone(),
                    params,
                )) as _
            }
            KeyStorageType::Pkcs11 => Arc::new(PKCS11KeyProvider::new()) as _,
            KeyStorageType::AzureVault => {
                let params = config.get(name)?;
                Arc::new(AzureVaultKeyProvider::new(params, crypto.clone())) as _
            }
            KeyStorageType::SecureElement => {
                if let Some(native_key_storage) = &secure_element_key_storage {
                    let params = config.get(name)?;
                    Arc::new(SecureElementKeyProvider::new(
                        native_key_storage.to_owned(),
                        params,
                    )) as _
                } else {
                    return Err(ConfigError::Validation(ConfigValidationError::InvalidKey(
                        name.to_string(),
                    )));
                }
            }
        };
        providers.insert(field.r#type.to_string(), provider);
    }

    for (key, value) in config.iter_mut() {
        if let Some(entity) = providers.get(&key.to_string()) {
            let json = serde_json::to_value(entity.get_capabilities())
                .map_err(|e| ConfigError::Parsing(ConfigParsingError::Json(e)))?;
            value.capabilities = Some(json);
        }
    }

    Ok(providers)
}

use std::collections::HashMap;
use std::sync::Arc;

use crate::config::core_config::{KeyStorageConfig, KeyStorageType};
use crate::config::ConfigValidationError;
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

pub struct GeneratedKey {
    pub public_key: Vec<u8>,
    pub key_reference: Vec<u8>,
}

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait KeyStorage {
    async fn generate(&self, key_id: &KeyId, key_type: &str) -> Result<GeneratedKey, ServiceError>;
    async fn sign(&self, key: &Key, message: &str) -> Result<Vec<u8>, SignerError>;
}

pub fn key_providers_from_config(
    config: &KeyStorageConfig,
    crypto: Arc<dyn CryptoProvider + Send + Sync>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider + Send + Sync>,
    secure_element_key_storage: Option<Arc<dyn NativeKeyStorage>>,
) -> Result<HashMap<String, Arc<dyn KeyStorage + Send + Sync>>, ConfigValidationError> {
    let mut providers: HashMap<String, Arc<dyn KeyStorage + Send + Sync>> = HashMap::new();

    for key_storage_type in config.as_inner().keys() {
        match key_storage_type {
            KeyStorageType::Internal => {
                let params = config.get(key_storage_type)?;

                let key_storage = Arc::new(InternalKeyProvider::new(
                    key_algorithm_provider.clone(),
                    params,
                ));

                providers.insert(key_storage_type.to_string(), key_storage);
            }
            KeyStorageType::Pkcs11 => {
                let key_storage = Arc::new(PKCS11KeyProvider::new());
                providers.insert(key_storage_type.to_string(), key_storage);
            }
            KeyStorageType::AzureVault => {
                let params = config.get(key_storage_type)?;
                let key_storage = Arc::new(AzureVaultKeyProvider::new(params, crypto.clone()));
                providers.insert(key_storage_type.to_string(), key_storage);
            }
            KeyStorageType::SecureElement => {
                if let Some(native_key_storage) = &secure_element_key_storage {
                    let params = config.get(key_storage_type)?;
                    let key_storage = Arc::new(SecureElementKeyProvider::new(
                        native_key_storage.to_owned(),
                        params,
                    ));
                    providers.insert(key_storage_type.to_string(), key_storage);
                } else {
                    return Err(ConfigValidationError::InvalidKey(
                        key_storage_type.to_string(),
                    ));
                }
            }
        }
    }

    Ok(providers)
}

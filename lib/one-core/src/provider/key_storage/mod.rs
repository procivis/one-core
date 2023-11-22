use std::collections::HashMap;
use std::sync::Arc;

use crate::config::core_config::{KeyStorageConfig, KeyStorageType};
use crate::config::ConfigValidationError;
use crate::crypto::signer::error::SignerError;
use crate::model::key::Key;
use crate::provider::key_storage::azure_vault::AzureVaultKeyProvider;
use crate::provider::key_storage::pkcs11::PKCS11KeyProvider;
use crate::{provider::key_storage::internal::InternalKeyProvider, service::error::ServiceError};

use super::key_algorithm::provider::KeyAlgorithmProvider;
use super::key_algorithm::GeneratedKey;

pub mod azure_vault;
pub mod internal;
pub mod pkcs11;
pub mod provider;

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait KeyStorage {
    async fn generate(&self, key_type: &str) -> Result<GeneratedKey, ServiceError>;
    async fn sign(&self, key: &Key, message: &str) -> Result<Vec<u8>, SignerError>;
}

pub fn key_providers_from_config(
    config: &KeyStorageConfig,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider + Send + Sync>,
) -> Result<HashMap<String, Arc<dyn KeyStorage + Send + Sync>>, ConfigValidationError> {
    let mut providers = HashMap::new();

    for key_storage_type in config.as_inner().keys() {
        match key_storage_type {
            KeyStorageType::Internal => {
                let params = config.get(key_storage_type)?;

                let key_storage = Arc::new(InternalKeyProvider::new(
                    key_algorithm_provider.clone(),
                    params,
                ));

                providers.insert(key_storage_type.to_string(), key_storage as _);
            }
            KeyStorageType::Pkcs11 => {
                let key_storage = Arc::new(PKCS11KeyProvider::new());
                providers.insert(key_storage_type.to_string(), key_storage as _);
            }
            KeyStorageType::AzureVault => {
                let key_storage = Arc::new(AzureVaultKeyProvider::new());
                providers.insert(key_storage_type.to_string(), key_storage as _);
            }
        }
    }

    Ok(providers)
}

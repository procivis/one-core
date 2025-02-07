//! Key storage provider.

use std::collections::HashMap;
use std::sync::Arc;

use one_crypto::SignerError;

use super::error::{KeyStorageError, KeyStorageProviderError};
use super::KeyStorage;
use crate::model::key::Key;
use crate::provider::credential_formatter::model::{AuthenticationFn, SignatureProvider};
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait KeyProvider: Send + Sync {
    fn get_key_storage(&self, key_provider_id: &str) -> Option<Arc<dyn KeyStorage>>;

    fn get_signature_provider(
        &self,
        key: &Key,
        jwk_key_id: Option<String>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    ) -> Result<AuthenticationFn, KeyStorageProviderError> {
        let key_handle = self
            .get_key_storage(&key.storage_type)
            .ok_or(KeyStorageProviderError::InvalidKeyStorage(
                key.storage_type.clone(),
            ))?
            .key_handle(key)
            .map_err(KeyStorageError::SignerError)?;

        Ok(Box::new(SignatureProviderImpl {
            key: key.to_owned(),
            key_handle,
            jwk_key_id,
            key_algorithm_provider,
        }))
    }
}

pub struct KeyProviderImpl {
    storages: HashMap<String, Arc<dyn KeyStorage>>,
}

impl KeyProviderImpl {
    pub fn new(storages: HashMap<String, Arc<dyn KeyStorage>>) -> Self {
        Self { storages }
    }
}

impl KeyProvider for KeyProviderImpl {
    fn get_key_storage(&self, format: &str) -> Option<Arc<dyn KeyStorage>> {
        self.storages.get(format).cloned()
    }
}

pub(crate) struct SignatureProviderImpl {
    pub key: Key,
    pub key_handle: KeyHandle,
    pub jwk_key_id: Option<String>,
    pub key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
}

#[async_trait::async_trait]
impl SignatureProvider for SignatureProviderImpl {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        self.key_handle.sign(message).await
    }

    fn get_key_id(&self) -> Option<String> {
        self.jwk_key_id.to_owned()
    }

    fn get_key_type(&self) -> &str {
        &self.key.key_type
    }

    fn jose_alg(&self) -> Option<String> {
        self.key_algorithm_provider
            .key_algorithm_from_name(&self.key.key_type)
            .and_then(|key_algorithm| key_algorithm.issuance_jose_alg_id())
    }

    fn get_public_key(&self) -> Vec<u8> {
        self.key.public_key.to_owned()
    }
}

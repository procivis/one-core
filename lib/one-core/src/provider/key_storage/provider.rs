use std::{collections::HashMap, sync::Arc};

use super::KeyStorage;
use crate::{
    crypto::signer::error::SignerError,
    model::key::Key,
    provider::credential_formatter::{AuthenticationFn, SignatureProvider},
    service::error::{ServiceError, ValidationError},
};

#[cfg_attr(test, mockall::automock)]
pub trait KeyProvider {
    fn get_key_storage(&self, key_provider_id: &str) -> Option<Arc<dyn KeyStorage>>;

    fn get_signature_provider(&self, key: &Key) -> Result<AuthenticationFn, ServiceError> {
        let storage = self
            .get_key_storage(&key.storage_type)
            .ok_or(ValidationError::InvalidKeyStorage(key.storage_type.clone()))?;

        Ok(Box::new(SignatureProviderImpl {
            key: key.to_owned(),
            storage,
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

struct SignatureProviderImpl {
    pub storage: Arc<dyn KeyStorage>,
    pub key: Key,
}

#[async_trait::async_trait]
impl SignatureProvider for SignatureProviderImpl {
    async fn sign(&self, message: &str) -> Result<Vec<u8>, SignerError> {
        self.storage.sign(&self.key, message).await
    }
}

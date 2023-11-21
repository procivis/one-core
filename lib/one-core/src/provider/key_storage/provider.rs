use std::{collections::HashMap, sync::Arc};

use super::KeyStorage;
use crate::{
    crypto::signer::error::SignerError,
    model::key::Key,
    provider::credential_formatter::{AuthenticationFn, SignatureProvider},
    service::error::ServiceError,
};

#[cfg_attr(test, mockall::automock)]
pub trait KeyProvider {
    fn get_key_storage(
        &self,
        key_provider_id: &str,
    ) -> Result<Arc<dyn KeyStorage + Send + Sync>, ServiceError>;

    fn get_signature_provider(&self, key: &Key) -> Result<AuthenticationFn, ServiceError> {
        let storage = self.get_key_storage(&key.storage_type)?;
        Ok(Box::new(SignatureProviderImpl {
            key: key.to_owned(),
            storage,
        }))
    }
}

pub struct KeyProviderImpl {
    storages: HashMap<String, Arc<dyn KeyStorage + Send + Sync>>,
}

impl KeyProviderImpl {
    pub fn new(storages: HashMap<String, Arc<dyn KeyStorage + Send + Sync>>) -> Self {
        Self { storages }
    }
}

impl KeyProvider for KeyProviderImpl {
    fn get_key_storage(
        &self,
        format: &str,
    ) -> Result<Arc<dyn KeyStorage + Send + Sync>, ServiceError> {
        Ok(self
            .storages
            .get(format)
            .ok_or(ServiceError::NotFound)?
            .clone())
    }
}

struct SignatureProviderImpl {
    pub storage: Arc<dyn KeyStorage + Send + Sync>,
    pub key: Key,
}

#[async_trait::async_trait]
impl SignatureProvider for SignatureProviderImpl {
    async fn sign(&self, message: &str) -> Result<Vec<u8>, SignerError> {
        self.storage.sign(&self.key, message).await
    }
}

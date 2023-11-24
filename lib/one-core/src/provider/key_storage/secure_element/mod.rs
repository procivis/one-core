use serde::Deserialize;
use std::sync::Arc;

use crate::{
    crypto::signer::error::SignerError,
    model::key::{Key, KeyId},
    provider::key_storage::{GeneratedKey, KeyStorage},
    service::error::ServiceError,
};

#[cfg_attr(test, mockall::automock)]
pub trait NativeKeyStorage: Send + Sync {
    fn generate_key(&self, key_alias: String) -> Result<GeneratedKey, ServiceError>;
    fn sign(&self, key_reference: &[u8], message: Vec<u8>) -> Result<Vec<u8>, SignerError>;
}

pub struct SecureElementKeyProvider {
    native_storage: Arc<dyn NativeKeyStorage>,
    params: Params,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    alias_prefix: String,
}

#[async_trait::async_trait]
impl KeyStorage for SecureElementKeyProvider {
    async fn generate(&self, key_id: &KeyId, key_type: &str) -> Result<GeneratedKey, ServiceError> {
        if key_type != "ES256" {
            return Err(ServiceError::IncorrectParameters);
        }

        let key_alias = format!("{}.{}", self.params.alias_prefix, key_id);
        self.native_storage.generate_key(key_alias)
    }

    async fn sign(&self, key: &Key, message: &str) -> Result<Vec<u8>, SignerError> {
        self.native_storage
            .sign(&key.key_reference, message.bytes().collect())
    }
}

impl SecureElementKeyProvider {
    pub fn new(native_storage: Arc<dyn NativeKeyStorage>, params: Params) -> Self {
        SecureElementKeyProvider {
            native_storage,
            params,
        }
    }
}

#[cfg(test)]
mod test;
use serde::Deserialize;
use std::sync::Arc;

use crate::{
    crypto::signer::error::SignerError,
    model::key::{Key, KeyId},
    provider::key_storage::{GeneratedKey, KeyStorage, KeyStorageCapabilities},
    service::error::{ServiceError, ValidationError},
};

#[cfg_attr(test, mockall::automock)]
pub trait NativeKeyStorage: Send + Sync {
    fn generate_key(&self, key_alias: String) -> Result<GeneratedKey, ServiceError>;
    fn sign(&self, key_reference: &[u8], message: Vec<u8>) -> Result<Vec<u8>, SignerError>;
}

pub struct SecureElementKeyProvider {
    capabilities: KeyStorageCapabilities,
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
            return Err(ValidationError::UnsupportedKeyType {
                key_type: key_type.to_owned(),
            }
            .into());
        }

        let key_alias = format!("{}.{}", self.params.alias_prefix, key_id);
        self.native_storage.generate_key(key_alias)
    }

    async fn sign(&self, key: &Key, message: &str) -> Result<Vec<u8>, SignerError> {
        self.native_storage
            .sign(&key.key_reference, message.bytes().collect())
    }

    fn get_capabilities(&self) -> KeyStorageCapabilities {
        self.capabilities.to_owned()
    }
}

impl SecureElementKeyProvider {
    pub fn new(
        capabilities: KeyStorageCapabilities,
        native_storage: Arc<dyn NativeKeyStorage>,
        params: Params,
    ) -> Self {
        SecureElementKeyProvider {
            capabilities,
            native_storage,
            params,
        }
    }
}

#[cfg(test)]
mod test;

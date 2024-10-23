use std::sync::Arc;

use one_crypto::SignerError;
use serde::Deserialize;
use shared_types::KeyId;
use zeroize::Zeroizing;

use crate::model::key::Key;
use crate::provider::key_storage::error::KeyStorageError;
use crate::provider::key_storage::model::{
    KeySecurity, KeyStorageCapabilities, StorageGeneratedKey,
};
use crate::provider::key_storage::KeyStorage;

#[cfg_attr(test, mockall::automock)]
pub trait NativeKeyStorage: Send + Sync {
    fn generate_key(&self, key_alias: String) -> Result<StorageGeneratedKey, KeyStorageError>;
    fn sign(&self, key_reference: &[u8], message: &[u8]) -> Result<Vec<u8>, SignerError>;
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
    async fn generate(
        &self,
        key_id: Option<KeyId>,
        key_type: &str,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        if key_type != "ES256" {
            return Err(KeyStorageError::UnsupportedKeyType {
                key_type: key_type.to_owned(),
            });
        }

        let key_id = key_id.ok_or(KeyStorageError::Failed("Missing key id".to_string()))?;

        let key_alias = format!("{}.{}", self.params.alias_prefix, key_id);
        let native_storage = Arc::clone(&self.native_storage);

        tokio::task::spawn_blocking(move || native_storage.generate_key(key_alias))
            .await
            .map_err(|error| SignerError::CouldNotSign(error.to_string()))?
    }

    async fn sign(&self, key: &Key, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        let native_storage = Arc::clone(&self.native_storage);
        let message = message.to_vec();
        let key_reference = key.key_reference.clone();

        tokio::task::spawn_blocking(move || native_storage.sign(&key_reference, &message))
            .await
            .map_err(|error| SignerError::CouldNotSign(error.to_string()))?
    }

    fn secret_key_as_jwk(&self, _key: &Key) -> Result<Zeroizing<String>, KeyStorageError> {
        unimplemented!()
    }

    fn get_capabilities(&self) -> KeyStorageCapabilities {
        KeyStorageCapabilities {
            algorithms: vec!["ES256".to_string()],
            security: vec![KeySecurity::Hardware],
            features: vec![],
        }
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

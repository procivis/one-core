use std::sync::Arc;

use one_crypto::SignerError;
use shared_types::KeyId;
use zeroize::Zeroizing;

use super::secure_element::NativeKeyStorage;
use crate::model::key::Key;
use crate::provider::key_storage::error::KeyStorageError;
use crate::provider::key_storage::model::{
    KeySecurity, KeyStorageCapabilities, StorageGeneratedKey,
};
use crate::provider::key_storage::KeyStorage;

pub struct RemoteSecureElementKeyProvider {
    native_storage: Arc<dyn NativeKeyStorage>,
}

#[async_trait::async_trait]
impl KeyStorage for RemoteSecureElementKeyProvider {
    async fn generate(
        &self,
        key_id: Option<KeyId>,
        key_type: &str,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        if key_type != "EDDSA" {
            return Err(KeyStorageError::UnsupportedKeyType {
                key_type: key_type.to_owned(),
            });
        }

        let key_id = key_id.ok_or(KeyStorageError::Failed("Missing key id".to_string()))?;
        self.native_storage.generate_key(key_id.to_string()).await
    }

    async fn sign(&self, key: &Key, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        self.native_storage
            .sign(&key.key_reference, message)
            .await
            .map_err(|error| SignerError::CouldNotSign(error.to_string()))
    }

    fn secret_key_as_jwk(&self, _key: &Key) -> Result<Zeroizing<String>, KeyStorageError> {
        unimplemented!()
    }

    fn get_capabilities(&self) -> KeyStorageCapabilities {
        KeyStorageCapabilities {
            algorithms: vec!["EDDSA".to_string()],
            security: vec![KeySecurity::Hardware],
            features: vec![],
        }
    }
}

impl RemoteSecureElementKeyProvider {
    pub fn new(native_storage: Arc<dyn NativeKeyStorage>) -> Self {
        Self { native_storage }
    }
}

#[cfg(test)]
mod test;

use one_providers::{
    common_models::key::{Key, KeyId},
    key_storage::{
        error::KeyStorageError,
        model::{KeyStorageCapabilities, StorageGeneratedKey},
        KeyStorage,
    },
};
use zeroize::Zeroizing;

use one_providers::crypto::SignerError;

#[derive(Default)]
pub struct PKCS11KeyProvider {}

#[async_trait::async_trait]
impl KeyStorage for PKCS11KeyProvider {
    async fn sign(&self, _key: &Key, _message: &[u8]) -> Result<Vec<u8>, SignerError> {
        todo!()
    }

    async fn generate(
        &self,
        _key_id: &KeyId,
        _key_type: &str,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        todo!()
    }

    fn secret_key_as_jwk(&self, _key: &Key) -> Result<Zeroizing<String>, KeyStorageError> {
        unimplemented!()
    }

    fn get_capabilities(&self) -> KeyStorageCapabilities {
        KeyStorageCapabilities::default()
    }
}

impl PKCS11KeyProvider {
    pub fn new() -> Self {
        PKCS11KeyProvider {}
    }
}

use shared_types::KeyId;
use zeroize::Zeroizing;

use crate::crypto::SignerError;
use crate::model::key::Key;
use crate::provider::key_storage::error::KeyStorageError;
use crate::provider::key_storage::model::{KeyStorageCapabilities, StorageGeneratedKey};
use crate::provider::key_storage::KeyStorage;

#[derive(Default)]
pub struct PKCS11KeyProvider {}

#[async_trait::async_trait]
impl KeyStorage for PKCS11KeyProvider {
    async fn sign(&self, _key: &Key, _message: &[u8]) -> Result<Vec<u8>, SignerError> {
        todo!()
    }

    async fn generate(
        &self,
        _key_id: Option<KeyId>,
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

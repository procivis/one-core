use one_crypto::SignerError;
use shared_types::KeyId;

use crate::model::key::Key;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_storage::KeyStorage;
use crate::provider::key_storage::error::KeyStorageError;
use crate::provider::key_storage::model::{KeyStorageCapabilities, StorageGeneratedKey};

#[derive(Default)]
pub struct PKCS11KeyProvider {}

#[async_trait::async_trait]
impl KeyStorage for PKCS11KeyProvider {
    fn get_capabilities(&self) -> KeyStorageCapabilities {
        KeyStorageCapabilities::default()
    }

    async fn generate(
        &self,
        _key_id: KeyId,
        _key_type: &str,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        todo!()
    }

    fn key_handle(&self, _key: &Key) -> Result<KeyHandle, SignerError> {
        todo!()
    }
}

impl PKCS11KeyProvider {
    pub fn new() -> Self {
        PKCS11KeyProvider {}
    }
}

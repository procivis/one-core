use one_crypto::SignerError;
use shared_types::KeyId;

use crate::config::core_config::KeyAlgorithmType;
use crate::model::key::{Key, PrivateKeyJwk};
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_storage::KeyStorage;
use crate::provider::key_storage::error::KeyStorageError;
use crate::provider::key_storage::model::{Features, KeyStorageCapabilities, StorageGeneratedKey};

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
        _key_type: KeyAlgorithmType,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        todo!()
    }

    async fn import(
        &self,
        _key_id: KeyId,
        _key_algorithm: KeyAlgorithmType,
        _jwk: PrivateKeyJwk,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        if !self
            .get_capabilities()
            .features
            .contains(&Features::Importable)
        {
            return Err(KeyStorageError::UnsupportedFeature {
                feature: Features::Importable,
            });
        }
        unimplemented!("import is not supported for PKCS11KeyProvider");
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

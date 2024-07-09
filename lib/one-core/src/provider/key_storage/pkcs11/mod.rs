use shared_types::KeyId;
use zeroize::Zeroizing;

use one_providers::crypto::SignerError;

use crate::provider::key_storage::KeyStorageCapabilities;
use crate::{model::key::Key, provider::key_storage::KeyStorage, service::error::ServiceError};

use super::StorageGeneratedKey;

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
    ) -> Result<StorageGeneratedKey, ServiceError> {
        todo!()
    }

    fn secret_key_as_jwk(&self, _key: &Key) -> Result<Zeroizing<String>, ServiceError> {
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

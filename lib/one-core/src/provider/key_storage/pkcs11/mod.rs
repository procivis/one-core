use crate::provider::key_storage::KeyStorageCapabilities;
use crate::{
    crypto::signer::error::SignerError,
    model::key::{Key, KeyId},
    provider::key_storage::{GeneratedKey, KeyStorage},
    service::error::ServiceError,
};

#[derive(Default)]
pub struct PKCS11KeyProvider {}

#[async_trait::async_trait]
impl KeyStorage for PKCS11KeyProvider {
    async fn sign(&self, _key: &Key, _message: &str) -> Result<Vec<u8>, SignerError> {
        todo!()
    }

    async fn generate(
        &self,
        _key_id: &KeyId,
        _key_type: &str,
    ) -> Result<GeneratedKey, ServiceError> {
        todo!()
    }

    fn get_capabilities(&self) -> KeyStorageCapabilities {
        todo!()
    }
}

impl PKCS11KeyProvider {
    pub fn new() -> Self {
        PKCS11KeyProvider {}
    }
}

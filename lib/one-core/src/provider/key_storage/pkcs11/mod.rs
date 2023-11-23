use crate::{
    crypto::signer::error::SignerError,
    model::key::Key,
    provider::{key_algorithm::GeneratedKey, key_storage::KeyStorage},
    service::error::ServiceError,
};

#[derive(Default)]
pub struct PKCS11KeyProvider {}

#[async_trait::async_trait]
impl KeyStorage for PKCS11KeyProvider {
    async fn sign(&self, _key: &Key, _message: &str) -> Result<Vec<u8>, SignerError> {
        todo!()
    }

    async fn generate(&self, _key_type: &str) -> Result<GeneratedKey, ServiceError> {
        todo!()
    }
}

impl PKCS11KeyProvider {
    pub fn new() -> Self {
        PKCS11KeyProvider {}
    }
}

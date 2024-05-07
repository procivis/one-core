use shared_types::KeyId;
use zeroize::Zeroizing;

use crate::provider::key_storage::dto::GenerateCSRRequestDTO;
use crate::provider::key_storage::KeyStorageCapabilities;
use crate::{
    crypto::signer::error::SignerError,
    model::key::Key,
    provider::key_storage::{GeneratedKey, KeyStorage},
    service::error::ServiceError,
};

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
    ) -> Result<GeneratedKey, ServiceError> {
        todo!()
    }

    fn secret_key_as_jwk(&self, _key: &Key) -> Result<Zeroizing<String>, ServiceError> {
        unimplemented!()
    }

    fn get_capabilities(&self) -> KeyStorageCapabilities {
        KeyStorageCapabilities::default()
    }

    async fn generate_x509_csr(
        &self,
        _key: &Key,
        _request: GenerateCSRRequestDTO,
    ) -> Result<String, ServiceError> {
        todo!()
    }
}

impl PKCS11KeyProvider {
    pub fn new() -> Self {
        PKCS11KeyProvider {}
    }
}

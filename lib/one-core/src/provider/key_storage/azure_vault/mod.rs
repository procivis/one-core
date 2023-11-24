use crate::{
    crypto::signer::error::SignerError,
    model::key::{Key, KeyId},
    provider::key_storage::{GeneratedKey, KeyStorage},
    service::error::ServiceError,
};

#[derive(Default)]
pub struct AzureVaultKeyProvider {}

#[async_trait::async_trait]
impl KeyStorage for AzureVaultKeyProvider {
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
}

impl AzureVaultKeyProvider {
    pub fn new() -> Self {
        Self {}
    }
}

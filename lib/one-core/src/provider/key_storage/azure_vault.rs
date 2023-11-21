use crate::{
    crypto::signer::error::SignerError,
    model::key::Key,
    provider::{key_algorithm::GeneratedKey, key_storage::KeyStorage},
    service::error::ServiceError,
};

#[derive(Default)]
pub struct AzureVaultKeyProvider {}

#[async_trait::async_trait]
impl KeyStorage for AzureVaultKeyProvider {
    async fn sign(&self, _key: &Key, _message: &str) -> Result<Vec<u8>, SignerError> {
        todo!()
    }

    async fn generate(&self, _key_type: &str) -> Result<GeneratedKey, ServiceError> {
        todo!()
    }
}

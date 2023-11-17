use crate::{
    provider::{key_algorithm::GeneratedKey, key_storage::KeyStorage},
    service::error::ServiceError,
};

#[derive(Default)]
pub struct AzureVaultKeyProvider {}

#[async_trait::async_trait]
impl KeyStorage for AzureVaultKeyProvider {
    async fn decrypt_private_key(&self, _private_key: &[u8]) -> Result<Vec<u8>, ServiceError> {
        todo!()
    }

    fn fingerprint(&self, _public_key: &[u8], _key_type: &str) -> Result<String, ServiceError> {
        todo!()
    }

    async fn generate(&self, _key_type: &str) -> Result<GeneratedKey, ServiceError> {
        todo!()
    }
}

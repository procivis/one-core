use crate::{
    provider::key_storage::{GeneratedKey, KeyStorage},
    service::error::ServiceError,
};

#[derive(Default)]
pub struct AzureVaultKeyProvider {}

impl KeyStorage for AzureVaultKeyProvider {
    fn decrypt_private_key(&self, _private_key: &[u8]) -> Result<Vec<u8>, ServiceError> {
        todo!()
    }

    fn fingerprint(&self, _public_key: &[u8]) -> String {
        todo!()
    }

    fn generate(&self, _algorithm: &str) -> Result<GeneratedKey, ServiceError> {
        todo!()
    }
}

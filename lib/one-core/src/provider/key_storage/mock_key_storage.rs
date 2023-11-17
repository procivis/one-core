use crate::{provider::key_algorithm::GeneratedKey, service::error::ServiceError};

use mockall::*;

#[derive(Default)]
pub struct KeyStorage;

mock! {
    pub KeyStorage {
        pub async fn decrypt_private_key(&self, private_key: &[u8]) -> Result<Vec<u8>, ServiceError>;
        pub fn fingerprint(&self, public_key: &[u8], key_type: &str) -> Result<String, ServiceError>;
        pub async fn generate(&self, key_type: &str) -> Result<GeneratedKey, ServiceError>;
    }
}

#[async_trait::async_trait]
impl crate::provider::key_storage::KeyStorage for MockKeyStorage {
    async fn decrypt_private_key(&self, private_key: &[u8]) -> Result<Vec<u8>, ServiceError> {
        self.decrypt_private_key(private_key).await
    }

    fn fingerprint(&self, public_key: &[u8], key_type: &str) -> Result<String, ServiceError> {
        self.fingerprint(public_key, key_type)
    }

    async fn generate(&self, key_type: &str) -> Result<GeneratedKey, ServiceError> {
        self.generate(key_type).await
    }
}

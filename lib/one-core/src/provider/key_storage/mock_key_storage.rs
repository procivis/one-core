use crate::{provider::key_storage::GeneratedKey, service::error::ServiceError};

use mockall::*;

#[derive(Default)]
pub struct KeyStorage;

mock! {
    pub KeyStorage {
        pub fn decrypt_private_key(&self, private_key: &[u8]) -> Result<Vec<u8>, ServiceError>;
        pub fn fingerprint(&self, public_key: &[u8]) -> Result<String, ServiceError>;
        pub fn generate(&self, algorithm: &str) -> Result<GeneratedKey, ServiceError>;
    }
}

impl crate::provider::key_storage::KeyStorage for MockKeyStorage {
    fn decrypt_private_key(&self, private_key: &[u8]) -> Result<Vec<u8>, ServiceError> {
        self.decrypt_private_key(private_key)
    }

    fn fingerprint(&self, public_key: &[u8]) -> Result<String, ServiceError> {
        self.fingerprint(public_key)
    }

    fn generate(&self, algorithm: &str) -> Result<GeneratedKey, ServiceError> {
        self.generate(algorithm)
    }
}

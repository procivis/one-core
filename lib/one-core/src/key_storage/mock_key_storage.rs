use crate::{key_storage::GeneratedKey, service::error::ServiceError};

use mockall::*;

#[derive(Default)]
pub struct KeyStorage;

mock! {
    pub KeyStorage {
        pub fn generate(&self, algorithm: &str) -> Result<GeneratedKey, ServiceError>;
    }
}

impl crate::key_storage::KeyStorage for MockKeyStorage {
    fn generate(&self, algorithm: &str) -> Result<GeneratedKey, ServiceError> {
        self.generate(algorithm)
    }
}

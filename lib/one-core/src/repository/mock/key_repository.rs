use crate::{model::key::KeyId, repository::error::DataLayerError};
use mockall::*;

#[derive(Default)]
struct KeyRepository;

mock! {
    pub KeyRepository {
        pub fn create_key(&self, request: crate::model::key::Key) -> Result<KeyId, DataLayerError>;
    }
}

#[async_trait::async_trait]
impl crate::repository::key_repository::KeyRepository for MockKeyRepository {
    async fn create_key(&self, request: crate::model::key::Key) -> Result<KeyId, DataLayerError> {
        self.create_key(request)
    }
}

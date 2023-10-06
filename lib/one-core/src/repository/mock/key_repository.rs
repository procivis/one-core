use crate::{
    model::key::{Key, KeyId, KeyRelations},
    repository::error::DataLayerError,
};
use mockall::*;

#[derive(Default)]
struct KeyRepository;

mock! {
    pub KeyRepository {
        pub fn create_key(&self, request: Key) -> Result<KeyId, DataLayerError>;
        pub fn get_key(&self, id: &KeyId, relations: &KeyRelations) -> Result<Key, DataLayerError>;
    }
}

#[async_trait::async_trait]
impl crate::repository::key_repository::KeyRepository for MockKeyRepository {
    async fn create_key(&self, request: Key) -> Result<KeyId, DataLayerError> {
        self.create_key(request)
    }

    async fn get_key(&self, id: &KeyId, relations: &KeyRelations) -> Result<Key, DataLayerError> {
        self.get_key(id, relations)
    }
}

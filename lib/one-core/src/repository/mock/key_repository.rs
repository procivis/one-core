use crate::{
    model::key::{
        GetKeyList, GetKeyQuery, KeyRelations, {Key, KeyId},
    },
    repository::error::DataLayerError,
};
use mockall::*;

#[derive(Default)]
struct KeyRepository;

mock! {
    pub KeyRepository {
        pub fn create_key(&self, request: Key) -> Result<KeyId, DataLayerError>;
        pub fn get_key(&self, id: &KeyId, relations: &KeyRelations) -> Result<Key, DataLayerError>;
        pub fn get_key_list(&self, query_params: GetKeyQuery) -> Result<GetKeyList, DataLayerError>;
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

    async fn get_key_list(&self, query_params: GetKeyQuery) -> Result<GetKeyList, DataLayerError> {
        self.get_key_list(query_params)
    }
}

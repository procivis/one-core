use super::error::DataLayerError;
use crate::model::key::{GetKeyList, GetKeyQuery, Key, KeyId, KeyRelations};

#[async_trait::async_trait]
pub trait KeyRepository: Send + Sync {
    async fn create_key(&self, request: Key) -> Result<KeyId, DataLayerError>;
    async fn get_key(
        &self,
        id: &KeyId,
        relations: &KeyRelations,
    ) -> Result<Option<Key>, DataLayerError>;
    async fn get_key_list(&self, query_params: GetKeyQuery) -> Result<GetKeyList, DataLayerError>;
}

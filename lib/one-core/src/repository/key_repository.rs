use std::sync::Arc;

use shared_types::KeyId;

use super::error::DataLayerError;
use crate::model::key::{GetKeyList, Key, KeyListQuery};
use crate::model::relation::AsyncModelLoader;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait KeyRepository: Send + Sync {
    async fn create_key(&self, request: Key) -> Result<KeyId, DataLayerError>;
    async fn get_key(&self, id: &KeyId) -> Result<Key, DataLayerError>;
    async fn get_keys(&self, ids: &[KeyId]) -> Result<Vec<Key>, DataLayerError>;
    async fn get_key_list(&self, query_params: KeyListQuery) -> Result<GetKeyList, DataLayerError>;
    async fn hard_delete(&self, id: &KeyId) -> Result<(), DataLayerError>;
}

#[async_trait::async_trait]
impl AsyncModelLoader<Key> for Arc<dyn KeyRepository> {
    async fn load(&self, id: &KeyId) -> Result<Key, DataLayerError> {
        self.get_key(id).await
    }
}

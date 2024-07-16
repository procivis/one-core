use super::error::DataLayerError;
use crate::model::key::{GetKeyList, GetKeyQuery, KeyRelations};
use one_providers::common_models::key::{Key, KeyId};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait KeyRepository: Send + Sync {
    async fn create_key(&self, request: Key) -> Result<KeyId, DataLayerError>;
    async fn get_key(
        &self,
        id: &KeyId,
        relations: &KeyRelations,
    ) -> Result<Option<Key>, DataLayerError>;
    async fn get_keys(&self, ids: &[KeyId]) -> Result<Vec<Key>, DataLayerError>;
    async fn get_key_list(&self, query_params: GetKeyQuery) -> Result<GetKeyList, DataLayerError>;
}

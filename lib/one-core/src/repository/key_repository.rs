use super::error::DataLayerError;
use crate::model::key::{GetKeyList, GetKeyQuery, KeyRelations};
use one_providers::common_models::key::{KeyId, OpenKey};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait KeyRepository: Send + Sync {
    async fn create_key(&self, request: OpenKey) -> Result<KeyId, DataLayerError>;
    async fn get_key(
        &self,
        id: &KeyId,
        relations: &KeyRelations,
    ) -> Result<Option<OpenKey>, DataLayerError>;
    async fn get_keys(&self, ids: &[KeyId]) -> Result<Vec<OpenKey>, DataLayerError>;
    async fn get_key_list(&self, query_params: GetKeyQuery) -> Result<GetKeyList, DataLayerError>;
}

use shared_types::RemoteEntityCacheId;

use super::error::DataLayerError;
use crate::model::remote_entity_cache::{CacheType, RemoteEntityCache, RemoteEntityCacheRelations};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait RemoteEntityCacheRepository: Send + Sync {
    async fn create(
        &self,
        request: RemoteEntityCache,
    ) -> Result<RemoteEntityCacheId, DataLayerError>;

    async fn delete_oldest(&self, r#type: CacheType) -> Result<(), DataLayerError>;

    async fn get_by_id(
        &self,
        id: &RemoteEntityCacheId,
        relations: &RemoteEntityCacheRelations,
    ) -> Result<Option<RemoteEntityCache>, DataLayerError>;

    async fn get_by_key(&self, key: &str) -> Result<Option<RemoteEntityCache>, DataLayerError>;

    async fn get_repository_size(&self, r#type: CacheType) -> Result<u32, DataLayerError>;

    async fn update(&self, request: RemoteEntityCache) -> Result<(), DataLayerError>;
}

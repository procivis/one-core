use shared_types::RemoteEntityCacheEntryId;

use super::error::DataLayerError;
use crate::model::remote_entity_cache::{
    CacheType, RemoteEntityCacheEntry, RemoteEntityCacheRelations,
};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait RemoteEntityCacheRepository: Send + Sync {
    async fn create(
        &self,
        request: RemoteEntityCacheEntry,
    ) -> Result<RemoteEntityCacheEntryId, DataLayerError>;

    async fn delete_oldest(&self, r#type: CacheType) -> Result<(), DataLayerError>;

    async fn delete_all(&self, r#type: Option<Vec<CacheType>>) -> Result<(), DataLayerError>;

    async fn get_by_id(
        &self,
        id: &RemoteEntityCacheEntryId,
        relations: &RemoteEntityCacheRelations,
    ) -> Result<Option<RemoteEntityCacheEntry>, DataLayerError>;

    async fn get_by_key(&self, key: &str)
    -> Result<Option<RemoteEntityCacheEntry>, DataLayerError>;

    async fn get_repository_size(&self, r#type: CacheType) -> Result<u32, DataLayerError>;

    async fn update(&self, request: RemoteEntityCacheEntry) -> Result<(), DataLayerError>;
}

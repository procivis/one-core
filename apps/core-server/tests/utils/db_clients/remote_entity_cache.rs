use std::sync::Arc;

use one_core::model::remote_entity_cache::RemoteEntityCacheEntry;
use one_core::repository::error::DataLayerError;
use one_core::repository::remote_entity_cache_repository::RemoteEntityCacheRepository;
use shared_types::RemoteEntityCacheEntryId;

pub struct RemoteEntityCacheDB {
    repository: Arc<dyn RemoteEntityCacheRepository>,
}

impl RemoteEntityCacheDB {
    pub fn new(repository: Arc<dyn RemoteEntityCacheRepository>) -> Self {
        Self { repository }
    }

    pub async fn add_entry(&self, entry: RemoteEntityCacheEntry) {
        self.repository.create(entry).await.expect("insert entry");
    }

    pub async fn get(&self, id: &RemoteEntityCacheEntryId) -> Option<RemoteEntityCacheEntry> {
        match self.repository.get_by_id(id).await {
            Ok(entry) => Some(entry),
            Err(DataLayerError::EntityNotFound { .. }) => None,
            Err(err) => panic!("get entry: {err}"),
        }
    }

    pub async fn get_by_key(&self, key: &str) -> Option<RemoteEntityCacheEntry> {
        self.repository
            .get_by_key(key)
            .await
            .expect("get entry by key")
    }
}

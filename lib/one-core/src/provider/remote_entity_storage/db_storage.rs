use std::sync::Arc;

use async_trait::async_trait;
use shared_types::RemoteEntityCacheEntryId;
use uuid::Uuid;

use crate::model::remote_entity_cache::RemoteEntityCacheEntry;
use crate::provider::remote_entity_storage::{
    RemoteEntity, RemoteEntityStorage, RemoteEntityStorageError, RemoteEntityType,
};
use crate::repository::error::DataLayerError;
use crate::repository::remote_entity_cache_repository::RemoteEntityCacheRepository;

pub struct DbStorage {
    remote_entity_cache_repository: Arc<dyn RemoteEntityCacheRepository>,
}

impl DbStorage {
    pub fn new(remote_entity_cache_repository: Arc<dyn RemoteEntityCacheRepository>) -> Self {
        Self {
            remote_entity_cache_repository,
        }
    }
}

#[async_trait]
impl RemoteEntityStorage for DbStorage {
    async fn delete_oldest(
        &self,
        entity_type: RemoteEntityType,
    ) -> Result<(), RemoteEntityStorageError> {
        self.remote_entity_cache_repository
            .delete_oldest(entity_type.into())
            .await
            .map_err(|e| RemoteEntityStorageError::Delete(e.to_string()))
    }

    async fn get_by_key(
        &self,
        key: &str,
    ) -> Result<Option<RemoteEntity>, RemoteEntityStorageError> {
        Ok(self
            .remote_entity_cache_repository
            .get_by_key(key)
            .await
            .map_err(|e| RemoteEntityStorageError::GetByKey(e.to_string()))?
            .map(Into::into))
    }

    async fn get_storage_size(
        &self,
        entity_type: RemoteEntityType,
    ) -> Result<usize, RemoteEntityStorageError> {
        Ok(self
            .remote_entity_cache_repository
            .get_repository_size(entity_type.into())
            .await
            .map_err(|e| RemoteEntityStorageError::GetStorageSize(e.to_string()))?
            as usize)
    }

    async fn insert(&self, request: RemoteEntity) -> Result<(), RemoteEntityStorageError> {
        if let Some(db_context) = self
            .remote_entity_cache_repository
            .get_by_key(&request.key)
            .await
            .map_err(|e| RemoteEntityStorageError::Insert(e.to_string()))?
        {
            self.remote_entity_cache_repository
                .update(storage_context_to_db_context(db_context.id, request))
                .await
                .map_err(|e| match e {
                    DataLayerError::RecordNotUpdated => RemoteEntityStorageError::NotUpdated,
                    e => RemoteEntityStorageError::Insert(e.to_string()),
                })?;
        } else {
            self.remote_entity_cache_repository
                .create(storage_context_to_db_context(
                    Uuid::new_v4().into(),
                    request,
                ))
                .await
                .map_err(|e| RemoteEntityStorageError::Insert(e.to_string()))?;
        }

        Ok(())
    }
}

fn storage_context_to_db_context(
    id: RemoteEntityCacheEntryId,
    storage_context: RemoteEntity,
) -> RemoteEntityCacheEntry {
    RemoteEntityCacheEntry {
        id,
        created_date: storage_context.last_modified,
        last_modified: storage_context.last_modified,
        value: storage_context.value,
        key: storage_context.key,
        hit_counter: storage_context.hit_counter,
        r#type: storage_context.entity_type.into(),
        media_type: storage_context.media_type,
        persistent: storage_context.persistent,
    }
}

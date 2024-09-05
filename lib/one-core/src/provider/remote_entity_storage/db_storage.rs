use std::sync::Arc;

use async_trait::async_trait;
use one_providers::remote_entity_storage::{
    RemoteEntity, RemoteEntityStorage, RemoteEntityStorageError, RemoteEntityType,
};
use shared_types::RemoteEntityCacheId;
use uuid::Uuid;

use crate::model;
use crate::repository::json_ld_context_repository::RemoteEntityCacheRepository;

pub struct DbStorage {
    remote_entity_cache_repository: Arc<dyn RemoteEntityCacheRepository>,
}

impl DbStorage {
    pub fn new(json_ld_context_repository: Arc<dyn RemoteEntityCacheRepository>) -> Self {
        Self {
            remote_entity_cache_repository: json_ld_context_repository,
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
            .map(db_context_to_storage_context))
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
                .map_err(|e| RemoteEntityStorageError::Insert(e.to_string()))?;
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

fn db_context_to_storage_context(
    db_context: model::remote_entity_cache::RemoteEntityCache,
) -> RemoteEntity {
    RemoteEntity {
        last_modified: db_context.last_modified,
        entity_type: db_context.r#type.into(),
        key: db_context.key,
        value: db_context.value,
        hit_counter: db_context.hit_counter,
    }
}

fn storage_context_to_db_context(
    id: RemoteEntityCacheId,
    storage_context: RemoteEntity,
) -> model::remote_entity_cache::RemoteEntityCache {
    model::remote_entity_cache::RemoteEntityCache {
        id,
        created_date: storage_context.last_modified,
        last_modified: storage_context.last_modified,
        value: storage_context.value,
        key: storage_context.key,
        hit_counter: storage_context.hit_counter,
        r#type: storage_context.entity_type.into(),
    }
}

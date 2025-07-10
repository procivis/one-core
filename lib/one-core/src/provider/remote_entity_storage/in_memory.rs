use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use itertools::Itertools;
use time::OffsetDateTime;
use tokio::sync::Mutex;

use super::{RemoteEntity, RemoteEntityStorage, RemoteEntityStorageError, RemoteEntityType};

pub struct InMemoryStorage {
    storage: Arc<Mutex<HashMap<String, RemoteEntity>>>,
}

impl InMemoryStorage {
    pub fn new(storage: HashMap<String, RemoteEntity>) -> Self {
        Self {
            storage: Arc::new(Mutex::new(storage)),
        }
    }
}

#[async_trait]
impl RemoteEntityStorage for InMemoryStorage {
    async fn delete_expired_or_least_used(
        &self,
        entity_type: RemoteEntityType,
        target_max_size: usize,
    ) -> Result<(), RemoteEntityStorageError> {
        let now = OffsetDateTime::now_utc();
        let mut hash_map_handle = self.storage.lock().await;

        // remove expired first
        hash_map_handle.retain(|_, val| {
            val.entity_type != entity_type
                || val.expiration_date.map(|exp| exp > now).unwrap_or(true)
        });

        let num_entries = hash_map_handle
            .iter()
            .filter(|(_, entity)| entity.entity_type == entity_type)
            .count();

        if num_entries <= target_max_size {
            // no need to remove by usage
            return Ok(());
        }

        let still_to_remove = num_entries - target_max_size;

        // remove oldest unused
        let to_remove: Vec<_> = hash_map_handle
            .iter()
            .filter(|(_, entity)| {
                entity.entity_type == entity_type && entity.expiration_date.is_some()
            })
            .sorted_by(|(_, a), (_, b)| a.last_used.cmp(&b.last_used))
            .map(|(key, _)| key.to_owned())
            .take(still_to_remove)
            .collect();

        hash_map_handle.retain(|key, _| !to_remove.contains(key));

        Ok(())
    }

    async fn get_by_key(
        &self,
        key: &str,
    ) -> Result<Option<RemoteEntity>, RemoteEntityStorageError> {
        let hash_map_handle = self.storage.lock().await;

        Ok(hash_map_handle.get(key).map(|v| v.to_owned()))
    }

    async fn get_storage_size(
        &self,
        entity_type: RemoteEntityType,
    ) -> Result<usize, RemoteEntityStorageError> {
        let hash_map_handle = self.storage.lock().await;

        Ok(hash_map_handle
            .iter()
            .filter(|(_, entity)| entity.entity_type == entity_type)
            .count())
    }

    async fn insert(&self, request: RemoteEntity) -> Result<(), RemoteEntityStorageError> {
        let mut hash_map_handle = self.storage.lock().await;

        hash_map_handle.insert(request.key.to_owned(), request);

        Ok(())
    }
}

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
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
    async fn delete_oldest(
        &self,
        entity_type: RemoteEntityType,
    ) -> Result<(), RemoteEntityStorageError> {
        let mut hash_map_handle = self.storage.lock().await;

        if let Some(key) = hash_map_handle
            .iter()
            .filter(|(_, entity)| entity.entity_type == entity_type)
            .min()
            .map(|(k, _)| k.to_owned())
        {
            hash_map_handle.remove(&key);
        }

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

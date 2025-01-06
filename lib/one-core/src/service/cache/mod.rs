use std::sync::Arc;

use crate::repository::remote_entity_cache_repository::RemoteEntityCacheRepository;

mod service;

#[derive(Clone)]
pub struct CacheService {
    remote_entity_cache_repository: Arc<dyn RemoteEntityCacheRepository>,
}

impl CacheService {
    pub fn new(remote_entity_cache_repository: Arc<dyn RemoteEntityCacheRepository>) -> Self {
        Self {
            remote_entity_cache_repository,
        }
    }
}

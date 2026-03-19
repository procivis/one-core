use std::sync::Arc;

use crate::error::ContextWithErrorCode;
use crate::provider::caching_loader::{CacheError, CachingLoader, Resolver, ResolverError};
use crate::provider::remote_entity_storage::{RemoteEntityStorage, RemoteEntityType};

pub struct EtsiLoteCache {
    inner: CachingLoader,
    resolver: Arc<dyn Resolver<Error = ResolverError>>,
}

impl EtsiLoteCache {
    pub fn new(
        resolver: Arc<dyn Resolver<Error = ResolverError>>,
        storage: Arc<dyn RemoteEntityStorage>,
        cache_size: usize,
        cache_refresh_timeout: time::Duration,
        refresh_after: time::Duration,
    ) -> Self {
        Self {
            inner: CachingLoader::new(
                RemoteEntityType::TrustList,
                storage,
                cache_size,
                cache_refresh_timeout,
                refresh_after,
            ),
            resolver,
        }
    }

    pub async fn get(&self, key: &str) -> Result<Vec<u8>, CacheError> {
        let (lote, _) = self
            .inner
            .get(key, self.resolver.clone(), false)
            .await
            .error_while("getting ETSI LoTE")?;

        Ok(lote)
    }
}

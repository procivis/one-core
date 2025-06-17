use std::sync::Arc;

use time::OffsetDateTime;

use super::{CachingLoader, CachingLoaderError, ResolveResult, Resolver};
use crate::provider::http_client::{self, HttpClient};
use crate::provider::remote_entity_storage::{
    RemoteEntityStorage, RemoteEntityStorageError, RemoteEntityType,
};

#[derive(Debug, thiserror::Error)]
pub enum X509CrlResolverError {
    #[error("Http client error: {0}")]
    HttpClient(#[from] http_client::Error),

    #[error("Failed deserializing response body: {0}")]
    InvalidResponseBody(#[from] serde_json::Error),

    #[error("Storage error: {0}")]
    Storage(#[from] RemoteEntityStorageError),

    #[error("Caching loader error: {0}")]
    CachingLoader(#[from] CachingLoaderError),
}

#[derive(Debug, thiserror::Error)]
pub enum X509CrlCacheError {
    #[error(transparent)]
    Resolver(#[from] X509CrlResolverError),

    #[error("Failed deserializing cached value: {0}")]
    InvalidCachedValue(#[from] serde_json::Error),
}

pub struct X509CrlCache {
    inner: CachingLoader<X509CrlResolverError>,
    resolver: Arc<dyn Resolver<Error = X509CrlResolverError>>,
}

impl X509CrlCache {
    pub fn new(
        resolver: Arc<dyn Resolver<Error = X509CrlResolverError>>,
        storage: Arc<dyn RemoteEntityStorage>,
        cache_size: usize,
        cache_refresh_timeout: time::Duration,
        refresh_after: time::Duration,
    ) -> Self {
        Self {
            inner: CachingLoader::new(
                RemoteEntityType::X509Crl,
                storage,
                cache_size,
                cache_refresh_timeout,
                refresh_after,
            ),
            resolver,
        }
    }

    pub async fn get(&self, key: &str) -> Result<Vec<u8>, X509CrlCacheError> {
        let (crl, _) = self.inner.get(key, self.resolver.clone(), false).await?;

        Ok(crl)
    }
}

pub struct X509CrlResolver {
    client: Arc<dyn HttpClient>,
}

impl X509CrlResolver {
    pub fn new(client: Arc<dyn HttpClient>) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl Resolver for X509CrlResolver {
    type Error = X509CrlResolverError;

    async fn do_resolve(
        &self,
        key: &str,
        _last_modified: Option<&OffsetDateTime>,
    ) -> Result<ResolveResult, Self::Error> {
        let response = self.client.get(key).send().await?.error_for_status()?;

        Ok(ResolveResult::NewValue {
            content: response.body,
            media_type: None,
        })
    }
}

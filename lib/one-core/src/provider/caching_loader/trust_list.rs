use std::sync::Arc;

use time::OffsetDateTime;

use super::{CachingLoader, CachingLoaderError, ResolveResult, Resolver};
use crate::provider::http_client::{self, HttpClient};
use crate::provider::remote_entity_storage::{
    RemoteEntityStorage, RemoteEntityStorageError, RemoteEntityType,
};

#[derive(Debug, thiserror::Error)]
pub enum TrustListResolverError {
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
pub enum TrustListCacheError {
    #[error(transparent)]
    Resolver(#[from] TrustListResolverError),

    #[error("Failed deserializing cached value: {0}")]
    InvalidCachedValue(#[from] serde_json::Error),
}

pub struct TrustListCache {
    inner: CachingLoader<TrustListResolverError>,
    resolver: Arc<dyn Resolver<Error = TrustListResolverError>>,
}

impl TrustListCache {
    pub fn new(
        resolver: Arc<dyn Resolver<Error = TrustListResolverError>>,
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

    pub async fn get(&self, key: &str) -> Result<serde_json::Value, TrustListResolverError> {
        let (schema, _) = self.inner.get(key, self.resolver.clone()).await?;

        Ok(serde_json::from_slice(&schema)?)
    }
}

pub struct TrustListResolver {
    client: Arc<dyn HttpClient>,
}

impl TrustListResolver {
    pub fn new(client: Arc<dyn HttpClient>) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl Resolver for TrustListResolver {
    type Error = TrustListResolverError;

    async fn do_resolve(
        &self,
        key: &str,
        _last_modified: Option<&OffsetDateTime>,
    ) -> Result<ResolveResult, Self::Error> {
        let response = self.client.get(key).send().await?.error_for_status()?;

        let media_type = response.header_get("content-type").map(|t| t.to_owned());

        let _: serde_json::Value = serde_json::from_slice(&response.body)?;

        Ok(ResolveResult::NewValue {
            content: response.body,
            media_type: Some(media_type.unwrap_or("application/json".to_string())),
        })
    }
}

use std::sync::Arc;

use serde::de::DeserializeOwned;
use time::OffsetDateTime;

use super::{CacheError, CachingLoader, ResolveResult, Resolver, ResolverError};
use crate::proto::http_client::HttpClient;
use crate::provider::caching_loader::InvalidCachedValueError;
use crate::provider::remote_entity_storage::{RemoteEntityStorage, RemoteEntityType};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait OpenIDMetadataFetcher: Send + Sync {
    async fn get(&self, url: &str) -> Result<Vec<u8>, CacheError>;
}

impl<'a> dyn OpenIDMetadataFetcher + 'a {
    pub(crate) async fn fetch<T: DeserializeOwned>(&self, url: &str) -> Result<T, CacheError> {
        let content = self.get(url).await?;
        serde_json::from_slice(&content)
            .map_err(|e| CacheError::InvalidCachedValue(InvalidCachedValueError::SerdeJson(e)))
    }
}

pub struct OpenIDMetadataCache {
    inner: CachingLoader,
    resolver: Arc<dyn Resolver<Error = ResolverError>>,
}

impl OpenIDMetadataCache {
    pub fn new(
        resolver: Arc<dyn Resolver<Error = ResolverError>>,
        storage: Arc<dyn RemoteEntityStorage>,
        cache_size: usize,
        cache_refresh_timeout: time::Duration,
        refresh_after: time::Duration,
    ) -> Self {
        Self {
            inner: CachingLoader::new(
                RemoteEntityType::OpenIDMetadata,
                storage,
                cache_size,
                cache_refresh_timeout,
                refresh_after,
            ),
            resolver,
        }
    }
}

#[async_trait::async_trait]
impl OpenIDMetadataFetcher for OpenIDMetadataCache {
    async fn get(&self, key: &str) -> Result<Vec<u8>, CacheError> {
        let (metadata, _) = self.inner.get(key, self.resolver.clone(), false).await?;

        Ok(metadata)
    }
}

pub struct OpenIDMetadataResolver {
    client: Arc<dyn HttpClient>,
}

impl OpenIDMetadataResolver {
    pub fn new(client: Arc<dyn HttpClient>) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl Resolver for OpenIDMetadataResolver {
    type Error = ResolverError;

    async fn do_resolve(
        &self,
        key: &str,
        _last_modified: Option<&OffsetDateTime>,
    ) -> Result<ResolveResult, Self::Error> {
        let response = self
            .client
            .get(key)
            .header("Accept", "application/json")
            .send()
            .await?
            .error_for_status()?;

        let media_type = response.header_get("content-type").map(|t| t.to_owned());
        let content = response.body;

        serde_json::from_slice::<serde_json::Value>(&content)?;

        Ok(ResolveResult::NewValue {
            content,
            media_type,
            expiry_date: None,
        })
    }
}

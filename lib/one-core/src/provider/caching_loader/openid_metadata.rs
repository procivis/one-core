use std::collections::HashMap;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use time::{Duration, OffsetDateTime};

use super::{CacheError, CachingLoader, ResolveResult, Resolver, ResolverError};
use crate::config::core_config::{CacheEntityCacheType, CacheEntityConfig, CoreConfig};
use crate::proto::http_client::HttpClient;
use crate::provider::caching_loader::InvalidCachedValueError;
use crate::provider::remote_entity_storage::db_storage::DbStorage;
use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
use crate::provider::remote_entity_storage::{RemoteEntityStorage, RemoteEntityType};
use crate::repository::remote_entity_cache_repository::RemoteEntityCacheRepository;

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

struct OpenIDMetadataCache {
    inner: CachingLoader,
    resolver: Arc<dyn Resolver<Error = ResolverError>>,
}

impl OpenIDMetadataCache {
    fn new(
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

struct OpenIDMetadataResolver {
    client: Arc<dyn HttpClient>,
}

impl OpenIDMetadataResolver {
    fn new(client: Arc<dyn HttpClient>) -> Self {
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

pub(crate) fn openid_metadata_cache_from_config(
    config: &CoreConfig,
    remote_entity_cache_repository: Arc<dyn RemoteEntityCacheRepository>,
    client: Arc<dyn HttpClient>,
) -> Arc<dyn OpenIDMetadataFetcher> {
    let config = config
        .cache_entities
        .entities
        .get("OPENID_METADATA")
        .cloned()
        .unwrap_or(CacheEntityConfig {
            cache_refresh_timeout: Duration::days(1),
            cache_size: 100,
            cache_type: CacheEntityCacheType::Db,
            refresh_after: Duration::minutes(5),
        });

    let storage: Arc<dyn RemoteEntityStorage> = match config.cache_type {
        CacheEntityCacheType::Db => Arc::new(DbStorage::new(remote_entity_cache_repository)),
        CacheEntityCacheType::InMemory => Arc::new(InMemoryStorage::new(HashMap::new())),
    };

    Arc::new(OpenIDMetadataCache::new(
        Arc::new(OpenIDMetadataResolver::new(client)),
        storage,
        config.cache_size as usize,
        config.cache_refresh_timeout,
        config.refresh_after,
    ))
}

use std::collections::HashMap;
use std::sync::Arc;

use time::OffsetDateTime;

use crate::config::core_config::{CacheEntityCacheType, CoreConfig};
use crate::error::ContextWithErrorCode;
use crate::proto::http_client::HttpClient;
use crate::proto::transaction_manager::TransactionManager;
use crate::proto::wallet_provider_client::http_client::dto::WalletProviderMetadataResponseRestDTO;
use crate::provider::caching_loader::{
    CacheError, CachingLoader, ResolveResult, Resolver, ResolverError,
};
use crate::provider::remote_entity_storage::db_storage::DbStorage;
use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
use crate::provider::remote_entity_storage::{RemoteEntityStorage, RemoteEntityType};
use crate::repository::remote_entity_cache_repository::RemoteEntityCacheRepository;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait WalletProviderMetadataCache: Send + Sync {
    async fn get(&self, key: &str) -> Result<WalletProviderMetadataResponseRestDTO, CacheError>;
}

pub struct WalletProviderMetadataCacheImpl {
    inner: CachingLoader,
    resolver: Arc<dyn Resolver<Error = ResolverError>>,
}

impl WalletProviderMetadataCacheImpl {
    pub fn new(
        caching_loader: CachingLoader,
        resolver: Arc<dyn Resolver<Error = ResolverError>>,
    ) -> Self {
        Self {
            inner: caching_loader,
            resolver,
        }
    }
}

#[async_trait::async_trait]
impl WalletProviderMetadataCache for WalletProviderMetadataCacheImpl {
    async fn get(&self, key: &str) -> Result<WalletProviderMetadataResponseRestDTO, CacheError> {
        let (data, _) = self
            .inner
            .get(key, self.resolver.clone(), false)
            .await
            .error_while("fetching wallet provider metadata")?;

        Ok(serde_json::from_slice(&data)?)
    }
}

pub fn wallet_provider_metadata_cache_from_config(
    client: Arc<dyn HttpClient>,
    remote_entity_cache_repository: Arc<dyn RemoteEntityCacheRepository>,
    config: &CoreConfig,
    transaction_manager: Arc<dyn TransactionManager>,
) -> WalletProviderMetadataCacheImpl {
    let config = config
        .cache_entities
        .entities
        .get("WALLET_PROVIDER_METADATA")
        .cloned()
        .unwrap_or_default();

    let storage: Arc<dyn RemoteEntityStorage> = match config.cache_type {
        CacheEntityCacheType::Db => Arc::new(DbStorage::new(
            remote_entity_cache_repository,
            transaction_manager,
        )),
        CacheEntityCacheType::InMemory => Arc::new(InMemoryStorage::new(HashMap::new())),
    };
    let inner = CachingLoader::new(
        RemoteEntityType::WalletProviderMetadata,
        storage,
        config.cache_size as usize,
        config.cache_refresh_timeout_seconds,
        config.refresh_after_seconds,
    );
    WalletProviderMetadataCacheImpl {
        inner,
        resolver: Arc::new(WalletProviderMetadataResolver::new(client)),
    }
}

pub struct WalletProviderMetadataResolver {
    client: Arc<dyn HttpClient>,
}

impl WalletProviderMetadataResolver {
    pub fn new(client: Arc<dyn HttpClient>) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl Resolver for WalletProviderMetadataResolver {
    type Error = ResolverError;

    async fn do_resolve(
        &self,
        key: &str,
        _last_modified: Option<&OffsetDateTime>,
    ) -> Result<ResolveResult, Self::Error> {
        let response = self
            .client
            .get(key)
            .send()
            .await
            .error_while("downloading wallet provider metadata")?
            .error_for_status()
            .error_while("downloading wallet provider metadata")?;

        let media_type = response.header_get("content-type").map(|t| t.to_owned());

        serde_json::from_slice::<serde_json::Value>(&response.body)?;

        Ok(ResolveResult::NewValue {
            content: response.body,
            media_type: Some(media_type.unwrap_or("application/json".to_string())),
            expiry_date: None,
        })
    }
}

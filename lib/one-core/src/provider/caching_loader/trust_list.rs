use std::sync::Arc;

use time::OffsetDateTime;

use super::{CacheError, CachingLoader, ResolveResult, Resolver, ResolverError};
use crate::error::ContextWithErrorCode;
use crate::proto::http_client::HttpClient;
use crate::provider::remote_entity_storage::{RemoteEntityStorage, RemoteEntityType};

pub struct TrustListCache {
    inner: CachingLoader,
    resolver: Arc<dyn Resolver<Error = ResolverError>>,
}

impl TrustListCache {
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

    pub async fn get(&self, key: &str) -> Result<serde_json::Value, CacheError> {
        let (schema, _) = self
            .inner
            .get(key, self.resolver.clone(), false)
            .await
            .error_while("getting trust list")?;

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
            .error_while("downloading trust list")?
            .error_for_status()
            .error_while("downloading trust list")?;

        let media_type = response.header_get("content-type").map(|t| t.to_owned());

        serde_json::from_slice::<serde_json::Value>(&response.body)?;

        Ok(ResolveResult::NewValue {
            content: response.body,
            media_type: Some(media_type.unwrap_or("application/json".to_string())),
            expiry_date: None,
        })
    }
}

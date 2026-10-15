use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use time::OffsetDateTime;
use url::Url;

use super::{CacheError, CachingLoader, ResolveResult, Resolver, ResolverError};
use crate::config::core_config::{CacheEntityCacheType, CoreConfig};
use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin};
use crate::proto::http_client::{HttpClient, is_media_type};
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::DecomposedJwt;
use crate::provider::remote_entity_storage::db_storage::DbStorage;
use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
use crate::provider::remote_entity_storage::{RemoteEntityStorage, RemoteEntityType};
use crate::repository::remote_entity_cache_repository::RemoteEntityCacheRepository;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait OpenIDMetadataFetcher: Send + Sync {
    async fn get(&self, url: &str, accept_mime: &str) -> Result<Vec<u8>, CacheError>;
}

impl<'a> dyn OpenIDMetadataFetcher + 'a {
    pub(crate) async fn fetch_json<T: DeserializeOwned>(&self, url: &str) -> Result<T, CacheError> {
        let content = self.get(url, "application/json").await?;
        Ok(serde_json::from_slice(&content)?)
    }

    pub(crate) async fn fetch_jwt<CustomPayload: DeserializeOwned + Debug>(
        &self,
        url: &str,
    ) -> Result<DecomposedJwt<CustomPayload>, CacheError> {
        let content = self.get(url, "application/jwt").await?;
        let jwt = String::from_utf8(content)?;
        Ok(Jwt::decompose_token(&jwt)?)
    }

    /// Fetches JSON metadata from the `.well-known/{well_known_path}` endpoint of `issuer_url`,
    /// falling back to the legacy endpoint if the standard one is unreachable.
    pub(crate) async fn fetch_json_well_known<T: DeserializeOwned>(
        &self,
        issuer_url: &Url,
        well_known_path: &str,
    ) -> Result<T, CacheError> {
        let endpoint = prepend_well_known_path(issuer_url, well_known_path);
        match self.fetch_json(&endpoint).await {
            Err(err) if is_endpoint_unavailable(&err) => {
                let fallback_endpoint = legacy_well_known_fallback(issuer_url, well_known_path)?;
                tracing::warn!(
                    "Failed to fetch from `{endpoint}`, falling back to legacy endpoint `{fallback_endpoint}`: {err}"
                );
                Ok(self
                    .fetch_json(&fallback_endpoint)
                    .await
                    .error_while("fetching metadata from fallback URL")?)
            }
            result => result,
        }
    }

    /// Fetches signed metadata from the `.well-known/{well_known_path}` endpoint of `issuer_url`,
    /// falling back to the legacy endpoint if the standard one is unreachable.
    pub(crate) async fn fetch_jwt_well_known<CustomPayload: DeserializeOwned + Debug>(
        &self,
        issuer_url: &Url,
        well_known_path: &str,
    ) -> Result<DecomposedJwt<CustomPayload>, CacheError> {
        let endpoint = prepend_well_known_path(issuer_url, well_known_path);
        match self.fetch_jwt(&endpoint).await {
            Err(err) if is_endpoint_unavailable(&err) => {
                let fallback_endpoint = legacy_well_known_fallback(issuer_url, well_known_path)?;
                tracing::warn!(
                    "Failed to fetch from `{endpoint}`, falling back to legacy endpoint `{fallback_endpoint}`: {err}"
                );
                Ok(self
                    .fetch_jwt(&fallback_endpoint)
                    .await
                    .error_while("fetching metadata from fallback URL")?)
            }
            result => result,
        }
    }
}

/// Whether the metadata endpoint could not be reached, meaning the legacy endpoint is worth a try.
fn is_endpoint_unavailable(error: &CacheError) -> bool {
    matches!(error.error_code(), ErrorCode::BR_0347 | ErrorCode::BR_0395)
}

/// `https://issuer.com/path` -> `https://issuer.com/.well-known/{well_known_path}/path`
fn prepend_well_known_path(issuer_url: &Url, well_known_path: &str) -> String {
    let origin = {
        let mut url = issuer_url.clone();
        url.set_path("");
        url.to_string()
    };
    // a trailing slash of the issuer URL would end up in the middle of the well-known URL
    let path = issuer_url.path().trim_end_matches('/');

    format!("{origin}.well-known/{well_known_path}{path}")
}

/// `https://issuer.com/path` -> `https://issuer.com/path/.well-known/{well_known_path}`
fn legacy_well_known_fallback(
    issuer_url: &Url,
    well_known_path: &str,
) -> Result<String, CacheError> {
    let mut url = issuer_url.to_owned();
    url.path_segments_mut()
        .map_err(|_| ResolverError::MappingError(format!("Invalid issuer URL: {issuer_url}")))
        .error_while("building legacy well-known URL")?
        // a trailing slash of the issuer URL would double up with the one added by `push`
        .pop_if_empty()
        .push(".well-known")
        .extend(well_known_path.split("/"));

    Ok(url.to_string())
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
                RemoteEntityType::OpenIdMetadataHolder,
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
    async fn get(&self, url: &str, accept_mime: &str) -> Result<Vec<u8>, CacheError> {
        let (metadata, _) = self
            .inner
            .get(&url_to_key(url, accept_mime), self.resolver.clone(), false)
            .await
            .error_while("getting OpenID metadata")?;

        Ok(metadata)
    }
}

fn url_to_key(url: &str, accept_mime: &str) -> String {
    format!("{accept_mime};{url}")
}

fn key_to_url(key: &str) -> Option<(Url, String)> {
    let (mime, url) = key.split_once(';')?;
    Some((url.parse().ok()?, mime.to_string()))
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
        let (url, accept_mime) =
            key_to_url(key).ok_or(ResolverError::MappingError("invalid key".to_string()))?;

        let response = self
            .client
            .get(url.as_str())
            .header("Accept", accept_mime.as_str())
            .send()
            .await
            .error_while("downloading OpenID metadata")?
            .error_for_status()
            .error_while("downloading OpenID metadata")?;

        let media_type = response.header_get("content-type").map(|t| t.to_owned());
        let content = response.body;

        if let Some(mime) = &media_type
            && !is_media_type(mime, &accept_mime)
        {
            return Err(ResolverError::InvalidResponse(format!(
                "Unexpected Content-Type: {mime}"
            )));
        }

        if accept_mime == "application/json" {
            serde_json::from_slice::<serde_json::Value>(&content)?;
        }

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
        .unwrap_or_default();

    let storage: Arc<dyn RemoteEntityStorage> = match config.cache_type {
        CacheEntityCacheType::Db => Arc::new(DbStorage::new(remote_entity_cache_repository)),
        CacheEntityCacheType::InMemory => Arc::new(InMemoryStorage::new(HashMap::new())),
    };

    Arc::new(OpenIDMetadataCache::new(
        Arc::new(OpenIDMetadataResolver::new(client)),
        storage,
        config.cache_size as usize,
        config.cache_refresh_timeout_seconds,
        config.refresh_after_seconds,
    ))
}

#[cfg(test)]
mod tests {
    use mockall::predicate::eq;
    use serde_json::json;
    use similar_asserts::assert_eq;

    use super::*;
    use crate::error::ErrorCodeMixinExt;
    use crate::proto::http_client;

    /// Error of an endpoint that could not be reached, i.e. one worth retrying on the legacy URL.
    fn unreachable_endpoint() -> CacheError {
        http_client::Error::Timeout.error_while("test").into()
    }

    fn fetcher(mock: MockOpenIDMetadataFetcher) -> Arc<dyn OpenIDMetadataFetcher> {
        Arc::new(mock)
    }

    #[tokio::test]
    async fn fetch_json_well_known_prepends_the_well_known_path() {
        // given
        let mut mock = MockOpenIDMetadataFetcher::new();
        mock.expect_get()
            .with(
                eq("https://issuer.com/.well-known/oauth-authorization-server/path"),
                eq("application/json"),
            )
            .once()
            .return_once(|_, _| {
                Ok(json!({ "issuer": "https://issuer.com" })
                    .to_string()
                    .into_bytes())
            });

        // when
        let metadata: serde_json::Value = fetcher(mock)
            .fetch_json_well_known(
                &"https://issuer.com/path".parse().unwrap(),
                "oauth-authorization-server",
            )
            .await
            .unwrap();

        // then
        assert_eq!(metadata["issuer"], "https://issuer.com");
    }

    #[tokio::test]
    async fn fetch_json_well_known_ignores_a_trailing_slash_of_the_issuer_url() {
        // given
        let mut mock = MockOpenIDMetadataFetcher::new();
        mock.expect_get()
            .with(
                eq("https://issuer.com/.well-known/oauth-authorization-server/path"),
                eq("application/json"),
            )
            .once()
            .return_once(|_, _| Err(unreachable_endpoint()));
        mock.expect_get()
            .with(
                eq("https://issuer.com/path/.well-known/oauth-authorization-server"),
                eq("application/json"),
            )
            .once()
            .return_once(|_, _| {
                Ok(json!({ "issuer": "https://issuer.com" })
                    .to_string()
                    .into_bytes())
            });

        // when
        let metadata: serde_json::Value = fetcher(mock)
            .fetch_json_well_known(
                &"https://issuer.com/path/".parse().unwrap(),
                "oauth-authorization-server",
            )
            .await
            .unwrap();

        // then
        assert_eq!(metadata["issuer"], "https://issuer.com");
    }

    #[tokio::test]
    async fn fetch_json_well_known_falls_back_to_the_legacy_endpoint() {
        // given
        let mut mock = MockOpenIDMetadataFetcher::new();
        mock.expect_get()
            .with(
                eq("https://issuer.com/.well-known/oauth-authorization-server/path"),
                eq("application/json"),
            )
            .once()
            .return_once(|_, _| Err(unreachable_endpoint()));
        mock.expect_get()
            .with(
                eq("https://issuer.com/path/.well-known/oauth-authorization-server"),
                eq("application/json"),
            )
            .once()
            .return_once(|_, _| {
                Ok(json!({ "issuer": "https://issuer.com" })
                    .to_string()
                    .into_bytes())
            });

        // when
        let metadata: serde_json::Value = fetcher(mock)
            .fetch_json_well_known(
                &"https://issuer.com/path".parse().unwrap(),
                "oauth-authorization-server",
            )
            .await
            .unwrap();

        // then
        assert_eq!(metadata["issuer"], "https://issuer.com");
    }

    #[tokio::test]
    async fn fetch_json_well_known_does_not_fall_back_on_unrelated_errors() {
        // given: the endpoint responded, but with something that is not JSON
        let mut mock = MockOpenIDMetadataFetcher::new();
        mock.expect_get()
            .with(
                eq("https://issuer.com/.well-known/oauth-authorization-server/path"),
                eq("application/json"),
            )
            .once()
            .return_once(|_, _| Ok(b"not json".to_vec()));

        // when
        let result = fetcher(mock)
            .fetch_json_well_known::<serde_json::Value>(
                &"https://issuer.com/path".parse().unwrap(),
                "oauth-authorization-server",
            )
            .await;

        // then: no second request against the legacy endpoint
        assert!(matches!(result, Err(CacheError::SerdeJson(_))));
    }

    #[tokio::test]
    async fn fetch_jwt_well_known_falls_back_to_the_legacy_endpoint() {
        // given
        let mut mock = MockOpenIDMetadataFetcher::new();
        mock.expect_get()
            .with(
                eq("https://issuer.com/.well-known/openid-credential-issuer/path"),
                eq("application/jwt"),
            )
            .once()
            .return_once(|_, _| Err(unreachable_endpoint()));
        // the legacy endpoint is tried next; the `once()` expectation asserts the request happens
        mock.expect_get()
            .with(
                eq("https://issuer.com/path/.well-known/openid-credential-issuer"),
                eq("application/jwt"),
            )
            .once()
            .return_once(|_, _| Ok(b"not-a-jwt".to_vec()));

        // when
        let result = fetcher(mock)
            .fetch_jwt_well_known::<serde_json::Value>(
                &"https://issuer.com/path".parse().unwrap(),
                "openid-credential-issuer",
            )
            .await;

        // then
        assert!(result.is_err());
    }
}

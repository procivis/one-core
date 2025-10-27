use std::string::FromUtf8Error;
use std::sync::Arc;

use async_trait::async_trait;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc2822;
use time::macros::offset;

use crate::proto::http_client::HttpClient;
use crate::provider::caching_loader::{CachingLoader, CachingLoaderError, ResolveResult, Resolver};
use crate::provider::remote_entity_storage::RemoteEntityStorageError;

pub struct JsonLdResolver {
    pub client: Arc<dyn HttpClient>,
}

impl JsonLdResolver {
    pub fn new(client: Arc<dyn HttpClient>) -> Self {
        Self { client }
    }
}

pub type JsonLdCachingLoader = CachingLoader<JsonLdResolverError>;

#[async_trait]
impl Resolver for JsonLdResolver {
    type Error = JsonLdResolverError;

    async fn do_resolve(
        &self,
        url: &str,
        last_modified: Option<&OffsetDateTime>,
    ) -> Result<ResolveResult, Self::Error> {
        let mut builder = self.client.get(url);

        if let Some(last_modified) = last_modified {
            builder = builder.header(
                "If-Modified-Since",
                &last_modified
                    .to_offset(offset!(+0))
                    .format(&RFC_2822_BUT_WITH_GMT)
                    .map_err(|e| JsonLdResolverError::TimeError(e.to_string()))?,
            );
        }

        let response = builder
            .send()
            .await
            .map_err(|e| JsonLdResolverError::Reqwest(e.to_string()))?
            .error_for_status()
            .map_err(|e| JsonLdResolverError::Reqwest(e.to_string()))?;
        if response.status.is_success() {
            Ok(ResolveResult::NewValue {
                content: response.body,
                media_type: None,
                expiry_date: None,
            })
        } else if response.status.is_redirection() {
            let result = response.header_get("Last-Modified");
            let last_modified = match result {
                None => OffsetDateTime::now_utc(),
                Some(value) => OffsetDateTime::parse(value, &Rfc2822)?,
            };
            Ok(ResolveResult::LastModificationDateUpdate(last_modified))
        } else {
            Err(JsonLdResolverError::UnexpectedStatusCode(
                response.status.to_string(),
            ))
        }
    }
}

#[derive(Clone, Debug, thiserror::Error)]
pub enum JsonLdResolverError {
    #[error("HTTP error: Cannot parse Last-Modified header")]
    CannotParseLastModifiedHeader,
    #[error("HTTP error: received 3xx status code when 2xx was expected")]
    ReceivedStatus3xxInsteadOf2xx,
    #[error("HTTP error: unexpected status code: `{0}`")]
    UnexpectedStatusCode(String),

    #[error("Caching loader error: `{0}`")]
    CachingLoaderError(#[from] CachingLoaderError),
    #[error("From UTF-8 error: `{0}`")]
    FromUtf8Error(#[from] FromUtf8Error),
    #[error("OffsetDateTime parse error: `{0}`")]
    OffsetDateTimeError(#[from] time::error::Parse),
    #[error("Remote entity storage error: `{0}`")]
    RemoteEntityStorageError(#[from] RemoteEntityStorageError),

    #[error("URL parse error: `{0}`")]
    UrlParseError(#[from] url::ParseError),

    /*
     * External errors which don't implement Clone on error types
     * Clone is required for interacting with sophia_jsonld
     */
    #[error("JSON parse error: `{0}`")]
    JsonParseError(String),
    #[error("MIME from str error: `{0}`")]
    MimeFromStrError(String),
    #[error("HTTP error: `{0}`")]
    Reqwest(String),
    #[error("Time error: `{0}`")]
    TimeError(String),
}

#[derive(Clone)]
pub struct ContextCache {
    loader: JsonLdCachingLoader,
    resolver: Arc<JsonLdResolver>,
}

impl ContextCache {
    pub fn new(loader: JsonLdCachingLoader, client: Arc<dyn HttpClient>) -> Self {
        Self {
            loader,
            resolver: Arc::new(JsonLdResolver { client }),
        }
    }
}

impl json_ld::Loader for ContextCache {
    async fn load(
        &self,
        url: &json_ld::Iri,
    ) -> Result<json_ld::RemoteDocument<json_ld::IriBuf>, json_ld::LoadError> {
        use json_ld::syntax::Parse;

        let (context, media_type) = self
            .loader
            .get(url, self.resolver.clone(), false)
            .await
            .map_err(|err| json_ld::LoadError::new(url.to_owned(), err))?;

        let document = json_ld::syntax::Value::parse_slice(&context)
            .map_err(|err| json_ld::LoadError::new(url.to_owned(), err))?
            .0;

        let content_type = media_type
            .as_deref()
            .unwrap_or("application/ld+json")
            .parse()
            .map(Some)
            .map_err(|err| json_ld::LoadError::new(url.to_owned(), err))?;

        Ok(json_ld::RemoteDocument::new(
            Some(url.to_owned()),
            content_type,
            document,
        ))
    }
}

const RFC_2822_BUT_WITH_GMT: &[time::format_description::FormatItem<'static>] = time::macros::format_description!(
    "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
);

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use reqwest::Client;
    use similar_asserts::assert_eq;
    use time::macros::datetime;
    use time::{Duration, OffsetDateTime};
    use wiremock::matchers::{headers, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::proto::http_client::MockHttpClient;
    use crate::proto::http_client::reqwest_client::ReqwestClient;
    use crate::provider::caching_loader::json_ld_context::{JsonLdCachingLoader, JsonLdResolver};
    use crate::provider::remote_entity_storage::{
        MockRemoteEntityStorage, RemoteEntity, RemoteEntityType,
    };

    pub fn get_dummy_date() -> OffsetDateTime {
        datetime!(2005-04-02 21:37 +1)
    }

    fn create_loader(
        storage: MockRemoteEntityStorage,
        cache_size: usize,
        cache_refresh_timeout: Duration,
        refresh_after: Duration,
    ) -> JsonLdCachingLoader {
        JsonLdCachingLoader::new(
            RemoteEntityType::JsonLdContext,
            Arc::new(storage),
            cache_size,
            cache_refresh_timeout,
            refresh_after,
        )
    }

    #[tokio::test]
    async fn test_load_context_success_cache_hit() {
        let url = "http://127.0.0.1/context";
        let response_content = "validstring";
        let expected_media_type = "MediaType";

        let mut storage = MockRemoteEntityStorage::default();
        storage.expect_get_by_key().return_once(|_| {
            let now = OffsetDateTime::now_utc();
            Ok(Some(RemoteEntity {
                last_modified: now,
                entity_type: RemoteEntityType::JsonLdContext,
                key: url.to_string(),
                value: response_content.to_string().into_bytes(),
                last_used: now,
                media_type: Some(expected_media_type.to_owned()),
                expiration_date: Some(now + Duration::days(1)),
            }))
        });

        storage.expect_insert().times(1).return_once(|_| Ok(()));
        storage
            .expect_delete_expired_or_least_used()
            .times(1)
            .return_once(|_, _| Ok(()));

        let loader = create_loader(
            storage,
            99999,
            Duration::seconds(99999),
            Duration::seconds(300),
        );

        let resolver = Arc::new(JsonLdResolver::new(Arc::new(MockHttpClient::new())));

        let (content, media_type) = loader.get(url, resolver, false).await.unwrap();

        assert_eq!(response_content, String::from_utf8(content).unwrap());
        assert_eq!(Some(expected_media_type), media_type.as_deref());
    }

    async fn context_fetch_mock_200(
        mock_server: &MockServer,
        result: &str,
        expect_if_modified_header: bool,
    ) {
        let mut mock = Mock::given(path("/context"));

        if expect_if_modified_header {
            mock = mock.and(headers(
                "if-modified-since",
                vec!["Sat", "02 Apr 2005 20:37:00 GMT"],
            ));
        }

        mock.respond_with(ResponseTemplate::new(200).set_body_string(result.to_string()))
            .expect(1)
            .mount(mock_server)
            .await;
    }

    async fn context_fetch_mock_304(mock_server: &MockServer) {
        Mock::given(path("/context"))
            .and(headers(
                "if-modified-since",
                vec!["Sat", "02 Apr 2005 20:37:00 GMT"],
            ))
            .respond_with(
                ResponseTemplate::new(304)
                    .insert_header("Last-Modified", "Sun, 02 Apr 2006 20:37:00 GMT"),
            )
            .expect(1)
            .mount(mock_server)
            .await;
    }

    async fn context_fetch_mock_304_without_last_modified_header(mock_server: &MockServer) {
        Mock::given(path("/context"))
            .and(headers(
                "if-modified-since",
                vec!["Sat", "02 Apr 2005 20:37:00 GMT"],
            ))
            .respond_with(ResponseTemplate::new(304))
            .expect(1)
            .mount(mock_server)
            .await;
    }

    #[tokio::test]
    async fn test_load_context_success_cache_miss_external_fetch_occured() {
        let response_content = "validstring";

        let mock_server = MockServer::start().await;
        context_fetch_mock_200(&mock_server, response_content, false).await;

        let url = format!("{}/context", mock_server.uri());

        let mut storage = MockRemoteEntityStorage::default();
        storage.expect_get_by_key().return_once(|_| Ok(None));

        storage.expect_insert().times(1).return_once(|_| Ok(()));
        storage
            .expect_delete_expired_or_least_used()
            .times(1)
            .return_once(|_, _| Ok(()));

        let loader = create_loader(
            storage,
            99999,
            Duration::seconds(99999),
            Duration::seconds(300),
        );

        let resolver = Arc::new(JsonLdResolver::new(Arc::new(ReqwestClient::default())));

        let (content, _media_type) = loader.get(&url, resolver, false).await.unwrap();

        assert_eq!(response_content, String::from_utf8(content).unwrap());
    }

    #[tokio::test]
    async fn test_load_context_success_cache_miss_overfilled_delete_oldest_entry_called() {
        let response_content = "validstring";

        let mock_server = MockServer::start().await;
        context_fetch_mock_200(&mock_server, response_content, false).await;

        let url = format!("{}/context", mock_server.uri());

        let mut storage = MockRemoteEntityStorage::default();
        storage.expect_get_by_key().return_once(|_| Ok(None));
        storage.expect_insert().times(1).return_once(|_| Ok(()));
        storage
            .expect_delete_expired_or_least_used()
            .times(1)
            .return_once(|_, _| Ok(()));

        let loader = create_loader(storage, 1, Duration::seconds(99999), Duration::seconds(300));

        let resolver = Arc::new(JsonLdResolver::new(Arc::new(ReqwestClient::default())));

        let (content, _media_type) = loader.get(&url, resolver, false).await.unwrap();

        assert_eq!(response_content, String::from_utf8(content).unwrap());
    }

    #[tokio::test]
    async fn test_load_context_success_cache_hit_but_too_old_200() {
        let old_response_content = "old_content";
        let response_content = "validstring";

        let mock_server = MockServer::start().await;
        context_fetch_mock_200(&mock_server, response_content, true).await;

        let url = format!("{}/context", mock_server.uri());

        let cloned_url = url.clone();
        let mut storage = MockRemoteEntityStorage::default();
        storage.expect_get_by_key().return_once(move |_| {
            Ok(Some(RemoteEntity {
                last_modified: get_dummy_date(),
                entity_type: RemoteEntityType::JsonLdContext,
                key: cloned_url,
                value: old_response_content.to_string().into_bytes(),
                last_used: get_dummy_date(),
                media_type: None,
                expiration_date: Some(OffsetDateTime::now_utc()),
            }))
        });
        storage.expect_insert().times(1).return_once(|request| {
            assert_eq!(request.value, response_content.to_string().into_bytes());
            assert!(request.last_modified > get_dummy_date());
            Ok(())
        });
        storage
            .expect_delete_expired_or_least_used()
            .times(1)
            .return_once(|_, _| Ok(()));

        let loader = create_loader(storage, 1, Duration::seconds(99999), Duration::seconds(300));

        let resolver = Arc::new(JsonLdResolver::new(Arc::new(ReqwestClient::default())));

        let (content, _media_type) = loader.get(&url, resolver, false).await.unwrap();

        assert_eq!(response_content, String::from_utf8(content).unwrap());
    }

    #[tokio::test]
    async fn test_load_context_success_cache_hit_but_too_old_304_with_last_modified_header() {
        let response_content = "validstring";

        let mock_server = MockServer::start().await;
        context_fetch_mock_304(&mock_server).await;

        let url = format!("{}/context", mock_server.uri());

        let cloned_url = url.clone();
        let mut storage = MockRemoteEntityStorage::default();
        storage.expect_get_by_key().return_once(move |_| {
            Ok(Some(RemoteEntity {
                last_modified: get_dummy_date(),
                value: response_content.to_string().into_bytes(),
                key: cloned_url,
                last_used: get_dummy_date(),
                entity_type: RemoteEntityType::JsonLdContext,
                media_type: None,
                expiration_date: Some(OffsetDateTime::now_utc()),
            }))
        });
        storage.expect_insert().times(1).return_once(|request| {
            assert_eq!(request.last_modified, datetime!(2006-04-02 21:37 +1));
            Ok(())
        });
        storage
            .expect_delete_expired_or_least_used()
            .times(1)
            .return_once(|_, _| Ok(()));

        let loader = create_loader(storage, 1, Duration::seconds(99999), Duration::seconds(300));
        let resolver = Arc::new(JsonLdResolver::new(Arc::new(ReqwestClient::default())));

        let (content, _media_type) = loader.get(&url, resolver, false).await.unwrap();

        assert_eq!(response_content, String::from_utf8(content).unwrap());
    }

    #[tokio::test]
    async fn test_load_context_success_cache_hit_but_too_old_304_without_last_modified_header() {
        let response_content = "validstring";

        let mock_server = MockServer::start().await;
        context_fetch_mock_304_without_last_modified_header(&mock_server).await;

        let url = format!("{}/context", mock_server.uri());

        let cloned_url = url.clone();
        let mut storage = MockRemoteEntityStorage::default();
        storage.expect_get_by_key().return_once(move |_| {
            Ok(Some(RemoteEntity {
                last_modified: get_dummy_date(),
                value: response_content.to_string().into_bytes(),
                key: cloned_url.parse().unwrap(),
                last_used: get_dummy_date(),
                entity_type: RemoteEntityType::JsonLdContext,
                media_type: None,
                expiration_date: Some(OffsetDateTime::now_utc()),
            }))
        });
        let now = OffsetDateTime::now_utc();
        storage
            .expect_insert()
            .times(1)
            .return_once(move |request| {
                assert!(request.last_modified > now);
                Ok(())
            });
        storage
            .expect_delete_expired_or_least_used()
            .times(1)
            .return_once(|_, _| Ok(()));

        let loader = create_loader(storage, 1, Duration::seconds(99999), Duration::seconds(300));
        let resolver = Arc::new(JsonLdResolver::new(Arc::new(ReqwestClient::default())));

        let (content, _media_type) = loader.get(&url, resolver, false).await.unwrap();

        assert_eq!(response_content, String::from_utf8(content).unwrap());
    }

    #[tokio::test]
    async fn test_load_context_success_cache_hit_older_than_refreshafter_younger_than_timeout() {
        let old_response_content = "old_content";

        let url = "http://127.0.0.2/context";

        let mut storage = MockRemoteEntityStorage::default();
        storage.expect_get_by_key().return_once(move |_| {
            Ok(Some(RemoteEntity {
                last_modified: get_dummy_date(),
                value: old_response_content.to_string().into_bytes(),
                key: url.to_string(),
                last_used: get_dummy_date(),
                entity_type: RemoteEntityType::JsonLdContext,
                media_type: None,
                expiration_date: Some(OffsetDateTime::now_utc() + Duration::days(1)),
            }))
        });
        storage.expect_insert().times(1).return_once(|request| {
            assert_eq!(request.value, old_response_content.to_string().into_bytes());
            Ok(())
        });
        storage
            .expect_delete_expired_or_least_used()
            .times(1)
            .return_once(|_, _| Ok(()));

        let refresh_timeout =
            OffsetDateTime::now_utc() - get_dummy_date() + Duration::seconds(99999);
        let loader = create_loader(storage, 1, refresh_timeout, Duration::seconds(300));
        let client = Client::builder()
            .timeout(core::time::Duration::from_millis(10))
            .build()
            .unwrap();
        let resolver = Arc::new(JsonLdResolver::new(Arc::new(ReqwestClient::new(client))));

        let (content, _media_type) = loader.get(url, resolver, false).await.unwrap();

        assert_eq!(old_response_content, String::from_utf8(content).unwrap());
    }

    #[tokio::test]
    async fn test_load_context_failed_cache_hit_older_than_refresh_after_and_failed_to_fetch() {
        let old_response_content = "old_content";

        let url = "http://127.0.0.2/context";

        let mut storage = MockRemoteEntityStorage::default();
        storage.expect_get_by_key().return_once(move |_| {
            Ok(Some(RemoteEntity {
                last_modified: get_dummy_date(),
                value: old_response_content.to_string().into_bytes(),
                key: url.to_string(),
                last_used: get_dummy_date(),
                entity_type: RemoteEntityType::JsonLdContext,
                media_type: None,
                expiration_date: Some(get_dummy_date()),
            }))
        });

        let loader = create_loader(
            storage,
            99999,
            Duration::seconds(301),
            Duration::seconds(300),
        );
        let client = Client::builder()
            .timeout(core::time::Duration::from_millis(10))
            .build()
            .unwrap();
        let resolver = Arc::new(JsonLdResolver::new(Arc::new(ReqwestClient::new(client))));

        assert!(loader.get(url, resolver, false).await.is_err());
    }

    #[tokio::test]
    async fn test_load_context_success_with_force_refresh() {
        let old_response_content = "old_content";
        let response_content = "validstring";

        let mock_server = MockServer::start().await;
        context_fetch_mock_200(&mock_server, response_content, false).await;

        let url = format!("{}/context", mock_server.uri());

        let mut storage = MockRemoteEntityStorage::default();

        // The force_refresh flag indicates that the remote source should be used even if the cached content is fresh.
        // The cache still needs to be consulted to make sure the bypassed entry is _not_ persistent.
        let key = url.to_string();
        let now = OffsetDateTime::now_utc();
        storage.expect_get_by_key().return_once(move |_| {
            Ok(Some(RemoteEntity {
                last_modified: now, // fresh copy
                value: old_response_content.to_string().into_bytes(),
                key,
                last_used: now,
                entity_type: RemoteEntityType::JsonLdContext,
                media_type: None,
                expiration_date: Some(now + Duration::days(1)),
            }))
        });

        storage.expect_insert().times(1).return_once(|_| Ok(()));
        storage
            .expect_delete_expired_or_least_used()
            .times(1)
            .return_once(|_, _| Ok(()));

        let loader = create_loader(
            storage,
            99999,
            Duration::seconds(99999),
            Duration::seconds(300),
        );

        let resolver = Arc::new(JsonLdResolver::new(Arc::new(ReqwestClient::default())));

        let (content, _media_type) = loader.get(&url, resolver, true).await.unwrap();

        assert_eq!(response_content, String::from_utf8(content).unwrap());
    }

    #[tokio::test]
    async fn test_load_persistent_context_success_with_force_refresh() {
        let old_response_content = "old_content";

        let mock_server = MockServer::start().await;
        let url = format!("{}/context", mock_server.uri());

        let mut storage = MockRemoteEntityStorage::default();

        // The force_refresh flag indicates that the remote source should be used even if the cached content is fresh.
        // The cache still needs to be consulted to make sure the bypassed entry is _not_ persistent.
        let key = url.to_string();
        let value = old_response_content.to_string().into_bytes();
        let now = OffsetDateTime::now_utc();
        storage.expect_get_by_key().return_once(move |_| {
            Ok(Some(RemoteEntity {
                last_modified: now,
                value,
                key,
                last_used: now,
                entity_type: RemoteEntityType::JsonLdContext,
                media_type: None,
                expiration_date: None,
            }))
        });

        // persistent entries must not be changed after the initial load and cannot be bypassed
        storage.expect_insert().never();
        storage
            .expect_delete_expired_or_least_used()
            .times(1)
            .return_once(|_, _| Ok(()));

        let loader = create_loader(
            storage,
            99999,
            Duration::seconds(99999),
            Duration::seconds(300),
        );

        let resolver = Arc::new(JsonLdResolver::new(Arc::new(ReqwestClient::default())));

        let (content, _media_type) = loader.get(&url, resolver, true).await.unwrap();

        assert_eq!(old_response_content, String::from_utf8(content).unwrap());
    }
}

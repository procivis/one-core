use std::sync::Arc;

use time::macros::datetime;
use time::{Duration, OffsetDateTime};
use wiremock::matchers::{headers, path};
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

use crate::provider::credential_formatter::json_ld::context::caching_loader::{
    JsonLdCachingLoader, JsonLdResolver,
};
use crate::provider::http_client::reqwest_client::ReqwestClient;
use crate::provider::http_client::MockHttpClient;
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
            hit_counter: 0,
            media_type: Some(expected_media_type.to_owned()),
            persistent: false,
        }))
    });

    storage.expect_insert().times(1).return_once(|_| Ok(()));
    storage
        .expect_get_storage_size()
        .times(1)
        .return_once(|_| Ok(1usize));

    let loader = create_loader(
        storage,
        99999,
        Duration::seconds(99999),
        Duration::seconds(300),
    );

    let resolver = Arc::new(JsonLdResolver::new(Arc::new(MockHttpClient::new())));

    let (content, media_type) = loader.get(url, resolver).await.unwrap();

    assert_eq!(response_content, String::from_utf8(content).unwrap());
    assert_eq!(Some(expected_media_type), media_type.as_deref());
}

pub struct CustomMatcher;

impl Match for CustomMatcher {
    fn matches(&self, request: &Request) -> bool {
        match request.headers.get("if-modified-since") {
            None => false,
            Some(value) => value == "Sat, 02 Apr 2005 20:37:00 GMT",
        }
    }
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
        .expect_get_storage_size()
        .times(1)
        .return_once(|_| Ok(1usize));

    let loader = create_loader(
        storage,
        99999,
        Duration::seconds(99999),
        Duration::seconds(300),
    );

    let resolver = Arc::new(JsonLdResolver::new(Arc::new(ReqwestClient::default())));

    let (content, _media_type) = loader.get(&url, resolver).await.unwrap();

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
        .expect_get_storage_size()
        .times(1)
        .return_once(|_| Ok(2usize));
    storage
        .expect_delete_oldest()
        .times(1)
        .return_once(|_| Ok(()));

    let loader = create_loader(storage, 1, Duration::seconds(99999), Duration::seconds(300));

    let resolver = Arc::new(JsonLdResolver::new(Arc::new(ReqwestClient::default())));

    let (content, _media_type) = loader.get(&url, resolver).await.unwrap();

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
            hit_counter: 0,
            media_type: None,
            persistent: false,
        }))
    });
    storage.expect_insert().times(1).return_once(|request| {
        assert_eq!(request.value, response_content.to_string().into_bytes());
        assert!(request.last_modified > get_dummy_date());
        Ok(())
    });
    storage
        .expect_get_storage_size()
        .times(1)
        .return_once(|_| Ok(2usize));
    storage
        .expect_delete_oldest()
        .times(1)
        .return_once(|_| Ok(()));

    let loader = create_loader(storage, 1, Duration::seconds(99999), Duration::seconds(300));

    let resolver = Arc::new(JsonLdResolver::new(Arc::new(ReqwestClient::default())));

    let (content, _media_type) = loader.get(&url, resolver).await.unwrap();

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
            hit_counter: 0,
            entity_type: RemoteEntityType::JsonLdContext,
            media_type: None,
            persistent: false,
        }))
    });
    storage.expect_insert().times(1).return_once(|request| {
        assert_eq!(request.last_modified, datetime!(2006-04-02 21:37 +1));
        Ok(())
    });
    storage
        .expect_get_storage_size()
        .times(1)
        .return_once(|_| Ok(2usize));
    storage
        .expect_delete_oldest()
        .times(1)
        .return_once(|_| Ok(()));

    let loader = create_loader(storage, 1, Duration::seconds(99999), Duration::seconds(300));
    let resolver = Arc::new(JsonLdResolver::new(Arc::new(ReqwestClient::default())));

    let (content, _media_type) = loader.get(&url, resolver).await.unwrap();

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
            hit_counter: 0,
            entity_type: RemoteEntityType::JsonLdContext,
            media_type: None,
            persistent: false,
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
        .expect_get_storage_size()
        .times(1)
        .return_once(|_| Ok(2usize));
    storage
        .expect_delete_oldest()
        .times(1)
        .return_once(|_| Ok(()));

    let loader = create_loader(storage, 1, Duration::seconds(99999), Duration::seconds(300));
    let resolver = Arc::new(JsonLdResolver::new(Arc::new(ReqwestClient::default())));

    let (content, _media_type) = loader.get(&url, resolver).await.unwrap();

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
            hit_counter: 0,
            entity_type: RemoteEntityType::JsonLdContext,
            media_type: None,
            persistent: false,
        }))
    });
    storage.expect_insert().times(1).return_once(|request| {
        assert_eq!(request.value, old_response_content.to_string().into_bytes());
        assert_eq!(request.hit_counter, 1);
        Ok(())
    });
    storage
        .expect_get_storage_size()
        .times(1)
        .return_once(|_| Ok(2usize));
    storage
        .expect_delete_oldest()
        .times(1)
        .return_once(|_| Ok(()));

    let refresh_timeout = OffsetDateTime::now_utc() - get_dummy_date() + Duration::seconds(99999);
    let loader = create_loader(storage, 1, refresh_timeout, Duration::seconds(300));
    let resolver = Arc::new(JsonLdResolver::new(Arc::new(ReqwestClient::default())));

    let (content, _media_type) = loader.get(url, resolver).await.unwrap();

    assert_eq!(old_response_content, String::from_utf8(content).unwrap());
}

#[tokio::test]
async fn test_load_context_failed_cache_hit_older_than_refreshafter_and_failed_to_fetch() {
    let old_response_content = "old_content";

    let url = "http://127.0.0.2/context";

    let mut storage = MockRemoteEntityStorage::default();
    storage.expect_get_by_key().return_once(move |_| {
        Ok(Some(RemoteEntity {
            last_modified: get_dummy_date(),
            value: old_response_content.to_string().into_bytes(),
            key: url.to_string(),
            hit_counter: 0,
            entity_type: RemoteEntityType::JsonLdContext,
            media_type: None,
            persistent: false,
        }))
    });

    let loader = create_loader(
        storage,
        99999,
        Duration::seconds(301),
        Duration::seconds(300),
    );
    let resolver = Arc::new(JsonLdResolver::new(Arc::new(ReqwestClient::default())));

    assert!(loader.get(url, resolver).await.is_err());
}

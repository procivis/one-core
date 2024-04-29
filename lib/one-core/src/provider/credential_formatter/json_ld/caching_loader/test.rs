use std::sync::Arc;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use wiremock::matchers::{headers, path};
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

use crate::model::json_ld_context::JsonLdContext;
use crate::provider::credential_formatter::json_ld::caching_loader::CachingLoader;
use crate::provider::credential_formatter::test_utilities::get_dummy_date;
use crate::repository::json_ld_context_repository::MockJsonLdContextRepository;

#[tokio::test]
async fn test_load_context_success_cache_hit() {
    let url = "http://127.0.0.1/context";
    let response_content = "validstring";

    let mut repository = MockJsonLdContextRepository::default();
    repository
        .expect_get_json_ld_context_by_url()
        .return_once(|_| {
            let now = OffsetDateTime::now_utc();
            Ok(Some(JsonLdContext {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                context: response_content.to_string().into_bytes(),
                url: url.parse().unwrap(),
                hit_counter: 0,
            }))
        });

    repository
        .expect_update_json_ld_context()
        .times(1)
        .return_once(|_| Ok(()));
    repository
        .expect_get_repository_size()
        .times(1)
        .return_once(|| Ok(1u32));

    let loader = CachingLoader {
        cache_size: 99999,
        cache_refresh_timeout: Duration::seconds(99999),
        client: Default::default(),
        json_ld_context_repository: Arc::new(repository),
    };

    assert_eq!(response_content, loader.load_context(url).await.unwrap());
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

#[tokio::test]
async fn test_load_context_success_cache_miss_external_fetch_occured() {
    let response_content = "validstring";

    let mock_server = MockServer::start().await;
    context_fetch_mock_200(&mock_server, response_content, false).await;

    let url = format!("{}/context", mock_server.uri());

    let mut repository = MockJsonLdContextRepository::default();
    repository
        .expect_get_json_ld_context_by_url()
        .return_once(|_| Ok(None));

    repository
        .expect_create_json_ld_context()
        .times(1)
        .return_once(|_| Ok(Uuid::new_v4().into()));
    repository
        .expect_get_repository_size()
        .times(1)
        .return_once(|| Ok(1u32));

    let loader = CachingLoader {
        cache_size: 99999,
        cache_refresh_timeout: Duration::seconds(99999),
        client: Default::default(),
        json_ld_context_repository: Arc::new(repository),
    };

    assert_eq!(response_content, loader.load_context(&url).await.unwrap());
}

#[tokio::test]
async fn test_load_context_success_cache_miss_overfilled_delete_oldest_entry_called() {
    let response_content = "validstring";

    let mock_server = MockServer::start().await;
    context_fetch_mock_200(&mock_server, response_content, false).await;

    let url = format!("{}/context", mock_server.uri());

    let mut repository = MockJsonLdContextRepository::default();
    repository
        .expect_get_json_ld_context_by_url()
        .return_once(|_| Ok(None));
    repository
        .expect_create_json_ld_context()
        .times(1)
        .return_once(|_| Ok(Uuid::new_v4().into()));
    repository
        .expect_get_repository_size()
        .times(1)
        .return_once(|| Ok(2u32));
    repository
        .expect_delete_oldest_context()
        .times(1)
        .return_once(|| Ok(()));

    let loader = CachingLoader {
        cache_size: 1,
        cache_refresh_timeout: Duration::seconds(99999),
        client: Default::default(),
        json_ld_context_repository: Arc::new(repository),
    };

    assert_eq!(response_content, loader.load_context(&url).await.unwrap());
}

#[tokio::test]
async fn test_load_context_success_cache_hit_but_too_old_200() {
    let old_response_content = "old_content";
    let response_content = "validstring";

    let mock_server = MockServer::start().await;
    context_fetch_mock_200(&mock_server, response_content, true).await;

    let url = format!("{}/context", mock_server.uri());

    let cloned_url = url.clone();
    let mut repository = MockJsonLdContextRepository::default();
    repository
        .expect_get_json_ld_context_by_url()
        .return_once(move |_| {
            Ok(Some(JsonLdContext {
                id: Uuid::new_v4().into(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                context: old_response_content.to_string().into_bytes(),
                url: cloned_url.parse().unwrap(),
                hit_counter: 0,
            }))
        });
    repository
        .expect_update_json_ld_context()
        .times(1)
        .return_once(|request| {
            assert_eq!(request.context, response_content.to_string().into_bytes());
            assert!(request.last_modified > get_dummy_date());
            Ok(())
        });
    repository
        .expect_get_repository_size()
        .times(1)
        .return_once(|| Ok(2u32));
    repository
        .expect_delete_oldest_context()
        .times(1)
        .return_once(|| Ok(()));

    let loader = CachingLoader {
        cache_size: 1,
        cache_refresh_timeout: Duration::seconds(99999),
        client: Default::default(),
        json_ld_context_repository: Arc::new(repository),
    };

    assert_eq!(response_content, loader.load_context(&url).await.unwrap());
}

#[tokio::test]
async fn test_load_context_success_cache_hit_but_too_old_304() {
    let response_content = "validstring";

    let mock_server = MockServer::start().await;
    context_fetch_mock_304(&mock_server).await;

    let url = format!("{}/context", mock_server.uri());

    let cloned_url = url.clone();
    let mut repository = MockJsonLdContextRepository::default();
    repository
        .expect_get_json_ld_context_by_url()
        .return_once(move |_| {
            Ok(Some(JsonLdContext {
                id: Uuid::new_v4().into(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                context: response_content.to_string().into_bytes(),
                url: cloned_url.parse().unwrap(),
                hit_counter: 0,
            }))
        });
    repository
        .expect_update_json_ld_context()
        .times(1)
        .return_once(|request| {
            assert_eq!(request.last_modified, datetime!(2006-04-02 21:37 +1));
            Ok(())
        });
    repository
        .expect_get_repository_size()
        .times(1)
        .return_once(|| Ok(2u32));
    repository
        .expect_delete_oldest_context()
        .times(1)
        .return_once(|| Ok(()));

    let loader = CachingLoader {
        cache_size: 1,
        cache_refresh_timeout: Duration::seconds(99999),
        client: Default::default(),
        json_ld_context_repository: Arc::new(repository),
    };

    assert_eq!(response_content, loader.load_context(&url).await.unwrap());
}

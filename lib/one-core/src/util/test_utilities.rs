use std::collections::HashMap;
use std::sync::Arc;

use mockall::predicate::{always, eq};
use time::{Duration, OffsetDateTime};

use crate::proto::http_client::{Method, MockHttpClient, RequestBuilder, Response};
use crate::provider::caching_loader::json_ld_context::JsonLdCachingLoader;
use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
use crate::provider::remote_entity_storage::{RemoteEntity, RemoteEntityType};

pub fn mock_http_get_request(http_client: &mut MockHttpClient, url: String, response: Response) {
    let mut new_client = MockHttpClient::new();
    new_client
        .expect_send()
        .with(eq(url.clone()), always(), always(), eq(Method::Get))
        .return_once(move |_, _, _, _| Ok(response));

    http_client
        .expect_get()
        .with(eq(url))
        .return_once(move |url| RequestBuilder::new(Arc::new(new_client), Method::Get, url));
}

pub fn prepare_caching_loader(additional: Option<(&str, &str)>) -> JsonLdCachingLoader {
    let now = OffsetDateTime::now_utc();
    let context = include_str!("context_vc2_0.jsonld");
    let mut contexts = vec![
        (
            "https://www.w3.org/ns/credentials/v2".to_string(),
            RemoteEntity {
                last_modified: now,
                entity_type: RemoteEntityType::JsonLdContext,
                key: "https://www.w3.org/ns/credentials/v2".to_string(),
                value: context.to_string().into_bytes(),
                last_used: now,
                media_type: None,
                expiration_date: Some(now + Duration::days(1)),
            },
        ),
        (
            "https://www.w3.org/ns/credentials/examples/v2".to_string(),
            RemoteEntity {
                last_modified: now,
                entity_type: RemoteEntityType::JsonLdContext,
                key: "https://www.w3.org/ns/credentials/examples/v2".to_string(),
                value: W3_ORG_NS_CREDENTIALS_EXAMPLES_V2.to_string().into_bytes(),
                last_used: now,
                media_type: None,
                expiration_date: Some(now + Duration::days(1)),
            },
        ),
    ];

    if let Some((id, content)) = additional {
        contexts.push((
            id.to_string(),
            RemoteEntity {
                last_modified: now,
                entity_type: RemoteEntityType::JsonLdContext,
                key: id.to_string(),
                value: content.to_string().into_bytes(),
                last_used: now,
                media_type: None,
                expiration_date: Some(now + Duration::days(1)),
            },
        ))
    }

    JsonLdCachingLoader::new(
        RemoteEntityType::JsonLdContext,
        Arc::new(InMemoryStorage::new(HashMap::from_iter(contexts))),
        10000,
        Duration::seconds(999999),
        Duration::seconds(300),
    )
}

#[allow(dead_code)]
pub(crate) fn assert_time_diff_less_than(
    time1: &OffsetDateTime,
    time2: &OffsetDateTime,
    max_diff: &Duration,
) {
    let diff = Duration::nanoseconds(
        (time1.unix_timestamp_nanos() - time2.unix_timestamp_nanos()).abs() as i64,
    );
    assert!(diff <= *max_diff)
}

const W3_ORG_NS_CREDENTIALS_EXAMPLES_V2: &str = r#"{
  "@context": {
    "@vocab": "https://www.w3.org/ns/credentials/examples#"
  }
}"#;

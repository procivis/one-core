use rstest::rstest;
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::*;
use crate::proto::http_client::MockHttpClient;
use crate::provider::did_method::provider::MockDidMethodProvider;

#[rstest]
#[case("https://example.com/", "example.com")]
#[case("https://example.com/a/b/c", "example.com:a:b:c")]
#[case("https://example.com/a/b/c/", "example.com:a:b:c")]
#[case("https://example.com:1234/a/b/c/", "example.com%3A1234:a:b:c")]
fn test_use_domain_with_external_host(#[case] external_hosting_url: &str, #[case] expected: &str) {
    let method = DidWebVh {
        params: Params {
            keys: Keys::default(),
            max_did_log_entry_check: None,
            resolve_to_insecure_http: false,
        },
        core_base_url: None,
        client: Arc::new(MockHttpClient::new()),
        did_method_provider: Arc::new(MockDidMethodProvider::new()),
        key_provider: None,
    };

    let did_id = Uuid::new_v4().into();
    let external_hosting_url = external_hosting_url.parse().unwrap();

    assert_eq!(
        method.domain(did_id, Some(external_hosting_url)).unwrap(),
        expected,
    )
}

#[rstest]
#[case(
    "http://core.dev.procivis-one.com",
    "core.dev.procivis-one.com:ssi:did-webvh:v1"
)]
#[case(
    "http://core.dev.procivis-one.com:9999",
    "core.dev.procivis-one.com%3A9999:ssi:did-webvh:v1"
)]
fn test_use_domain_with_core_base_url(#[case] base_url: &str, #[case] expected: &str) {
    let method = DidWebVh {
        params: Params::default(),
        core_base_url: Some(base_url.to_string()),
        client: Arc::new(MockHttpClient::new()),
        did_method_provider: Arc::new(MockDidMethodProvider::new()),
        key_provider: None,
    };

    let did_id = Uuid::new_v4().into();
    let expected = format!("{expected}:{did_id}");
    assert_eq!(method.domain(did_id, None).unwrap(), expected)
}

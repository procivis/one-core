use rstest::rstest;
use uuid::Uuid;

use super::*;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::http_client::MockHttpClient;

#[test]
fn test_use_domain_with_external_host() {
    let method = DidWebVh {
        params: Params {
            max_did_log_entry_check: None,
            external_hosting_url: Some("test-external.com".to_string()),
        },
        core_base_url: None,
        client: Arc::new(MockHttpClient::new()),
        did_method_provider: Arc::new(MockDidMethodProvider::new()),
        key_provider: None,
    };

    let did_id = Uuid::new_v4().into();
    let expected = format!("test-external.com:{did_id}");
    assert_eq!(method.domain(did_id).unwrap(), expected,)
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
    assert_eq!(method.domain(did_id).unwrap(), expected)
}

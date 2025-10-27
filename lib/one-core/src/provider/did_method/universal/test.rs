use std::sync::Arc;

use similar_asserts::assert_eq;

use crate::proto::http_client::MockHttpClient;
use crate::provider::did_method::DidMethod;
use crate::provider::did_method::model::Operation;
use crate::provider::did_method::universal::{Params, UniversalDidMethod};

#[test]
fn test_get_capabilities() {
    let provider = UniversalDidMethod::new(
        Params {
            resolver_url: "".into(),
            supported_method_names: vec!["ion".to_string()],
        },
        Arc::new(MockHttpClient::new()),
    );

    assert_eq!(
        vec![Operation::RESOLVE],
        provider.get_capabilities().operations
    );
    assert_eq!(provider.get_capabilities().method_names, vec!["ion"]);
}

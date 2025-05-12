use std::sync::Arc;

use crate::provider::did_method::DidMethod;
use crate::provider::did_method::model::Operation;
use crate::provider::did_method::universal::{Params, UniversalDidMethod};
use crate::provider::http_client::MockHttpClient;

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

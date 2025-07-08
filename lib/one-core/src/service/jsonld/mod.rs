use std::sync::Arc;

use crate::provider::caching_loader::json_ld_context::{JsonLdCachingLoader, JsonLdResolver};
use crate::provider::http_client::HttpClient;

pub mod service;

pub struct JsonLdService {
    caching_loader: JsonLdCachingLoader,
    resolver: Arc<JsonLdResolver>,
}

impl JsonLdService {
    pub fn new(caching_loader: JsonLdCachingLoader, client: Arc<dyn HttpClient>) -> Self {
        Self {
            caching_loader,
            resolver: Arc::new(JsonLdResolver { client }),
        }
    }
}

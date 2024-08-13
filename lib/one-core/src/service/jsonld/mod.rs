use std::sync::Arc;

use one_providers::credential_formatter::imp::json_ld::context::caching_loader::{
    JsonLdCachingLoader, JsonLdResolver,
};

pub mod service;

pub struct JsonLdService {
    caching_loader: JsonLdCachingLoader,
    resolver: Arc<JsonLdResolver>,
}

impl JsonLdService {
    pub fn new(caching_loader: JsonLdCachingLoader) -> Self {
        Self {
            caching_loader,
            resolver: Arc::new(JsonLdResolver {
                client: reqwest::Client::new(),
            }),
        }
    }
}

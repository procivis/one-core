use one_providers::credential_formatter::imp::json_ld::context::caching_loader::JsonLdCachingLoader;

pub mod service;

pub struct JsonLdService {
    caching_loader: JsonLdCachingLoader,
}

impl JsonLdService {
    pub fn new(caching_loader: JsonLdCachingLoader) -> Self {
        Self { caching_loader }
    }
}

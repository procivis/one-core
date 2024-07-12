use crate::provider::credential_formatter::json_ld::caching_loader::CachingLoader;

pub mod service;

pub struct JsonLdService {
    caching_loader: CachingLoader,
}

impl JsonLdService {
    pub fn new(caching_loader: CachingLoader) -> Self {
        Self { caching_loader }
    }
}

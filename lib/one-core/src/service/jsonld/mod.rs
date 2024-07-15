use one_providers::credential_formatter::imp::json_ld::context::caching_loader::CachingLoader;

pub mod service;

pub struct JsonLdService {
    caching_loader: CachingLoader,
}

impl JsonLdService {
    pub fn new(caching_loader: CachingLoader) -> Self {
        Self { caching_loader }
    }
}

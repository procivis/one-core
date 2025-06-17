#[derive(Clone)]
pub struct OneCoreConfig {
    pub caching_config: CachingConfig,
    pub did_method_config: DidMethodConfig,
    pub formatter_config: FormatterConfig,
}

#[derive(Clone)]
pub struct CachingLoaderConfig {
    pub cache_size: usize,
    pub cache_refresh_timeout: time::Duration,
    pub refresh_after: time::Duration,
}

#[derive(Clone)]
pub struct CachingConfig {
    pub did: CachingLoaderConfig,
    pub json_ld_context: CachingLoaderConfig,
    pub x509_crl: CachingLoaderConfig,
}

#[derive(Clone)]
pub struct DidMethodConfig {
    pub universal_resolver_url: String,
    pub key_count_range: (usize, usize),
}

#[derive(Clone)]
pub struct FormatterConfig {
    pub leeway: u64,
    pub embed_layout_properties: bool,
}

impl Default for OneCoreConfig {
    fn default() -> Self {
        Self {
            caching_config: CachingConfig {
                did: CachingLoaderConfig {
                    cache_size: 100,
                    cache_refresh_timeout: time::Duration::days(1),
                    refresh_after: time::Duration::minutes(5),
                },
                json_ld_context: CachingLoaderConfig {
                    cache_size: 100,
                    cache_refresh_timeout: time::Duration::days(10),
                    refresh_after: time::Duration::days(1),
                },
                x509_crl: CachingLoaderConfig {
                    cache_size: 100,
                    cache_refresh_timeout: time::Duration::days(1),
                    refresh_after: time::Duration::days(1),
                },
            },
            did_method_config: DidMethodConfig {
                universal_resolver_url: "https://dev.uniresolver.io".to_string(),
                key_count_range: (1, 1),
            },
            formatter_config: FormatterConfig {
                leeway: 60,
                embed_layout_properties: false,
            },
        }
    }
}

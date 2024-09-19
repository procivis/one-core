pub struct OneCoreConfig {
    pub caching_config: CachingConfig,
    pub did_method_config: DidMethodConfig,
    pub formatter_config: FormatterConfig,
}

pub struct CachingLoaderConfig {
    pub cache_size: usize,
    pub cache_refresh_timeout: time::Duration,
    pub refresh_after: time::Duration,
}

pub struct CachingConfig {
    pub did: CachingLoaderConfig,
    pub json_ld_context: CachingLoaderConfig,
}

pub struct DidMethodConfig {
    pub universal_resolver_url: String,
    pub key_count_range: (usize, usize),
}

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

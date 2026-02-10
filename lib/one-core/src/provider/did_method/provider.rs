//! DID method provider.

use std::collections::HashMap;
use std::sync::Arc;

use indexmap::IndexMap;
use serde_json::json;
use shared_types::DidValue;
use time::Duration;

use super::dto::DidDocumentDTO;
use super::error::DidMethodProviderError;
use super::jwk::JWKDidMethod;
use super::key::KeyDidMethod;
use super::model::DidDocument;
use super::resolver::{DidCachingLoader, DidResolver};
use super::universal::UniversalDidMethod;
use super::web::WebDidMethod;
use super::{DidMethod, universal, web, webvh};
use crate::config::core_config::{
    CacheEntitiesConfig, CacheEntityCacheType, CacheEntityConfig, CoreConfig, DidType, Fields,
};
use crate::config::{ConfigValidationError, core_config};
use crate::error::ContextWithErrorCode;
use crate::proto::http_client::HttpClient;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::remote_entity_storage::db_storage::DbStorage;
use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
use crate::provider::remote_entity_storage::{RemoteEntityStorage, RemoteEntityType};
use crate::repository::remote_entity_cache_repository::RemoteEntityCacheRepository;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait DidMethodProvider: Send + Sync {
    fn get_did_method(&self, did_method_id: &str) -> Option<Arc<dyn DidMethod>>;

    fn get_did_method_id(&self, did: &DidValue) -> Option<String>;

    fn get_did_method_by_method_name(
        &self,
        method_name: &str,
    ) -> Option<(String, Arc<dyn DidMethod>)>;

    async fn resolve(&self, did: &DidValue) -> Result<DidDocument, DidMethodProviderError>;

    fn supported_method_names(&self) -> Vec<String>;
}

struct DidMethodProviderImpl {
    caching_loader: DidCachingLoader,
    did_methods: IndexMap<String, Arc<dyn DidMethod>>,
    resolver: Arc<DidResolver>,
}

impl DidMethodProviderImpl {
    fn new(
        caching_loader: DidCachingLoader,
        did_methods: IndexMap<String, Arc<dyn DidMethod>>,
    ) -> Self {
        let resolver = DidResolver {
            did_methods: did_methods.clone(),
        };

        Self {
            caching_loader,
            did_methods,
            resolver: Arc::new(resolver),
        }
    }
}

#[async_trait::async_trait]
impl DidMethodProvider for DidMethodProviderImpl {
    fn get_did_method(&self, did_method_id: &str) -> Option<Arc<dyn DidMethod>> {
        self.did_methods.get(did_method_id).cloned()
    }

    fn get_did_method_id(&self, did: &DidValue) -> Option<String> {
        self.did_methods
            .iter()
            .find(|(_, method)| {
                method
                    .get_capabilities()
                    .method_names
                    .iter()
                    .any(|v| v == did.method())
            })
            .map(|(id, _)| id.clone())
    }

    fn get_did_method_by_method_name(
        &self,
        method_name: &str,
    ) -> Option<(String, Arc<dyn DidMethod>)> {
        self.did_methods
            .iter()
            .find(|(_, method)| {
                method
                    .get_capabilities()
                    .method_names
                    .contains(&method_name.to_string())
            })
            .map(|(id, method)| (id.clone(), method.clone()))
    }

    async fn resolve(&self, did: &DidValue) -> Result<DidDocument, DidMethodProviderError> {
        let (content, _media_type) = self
            .caching_loader
            .get(did.as_str(), self.resolver.clone(), false)
            .await
            .error_while("resolving did")?;
        let dto: DidDocumentDTO = serde_json::from_slice(&content)?;
        Ok(dto.into())
    }

    fn supported_method_names(&self) -> Vec<String> {
        self.did_methods
            .values()
            .flat_map(|did_method| did_method.get_capabilities().method_names)
            .collect()
    }
}

pub(crate) fn did_method_provider_from_config(
    config: &mut CoreConfig,
    core_base_url: Option<String>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    key_provider: Arc<dyn KeyProvider>,
    client: Arc<dyn HttpClient>,
    remote_entity_cache_repository: Arc<dyn RemoteEntityCacheRepository>,
) -> Result<Arc<dyn DidMethodProvider>, ConfigValidationError> {
    let mut did_configs = config.did.iter().collect::<Vec<_>>();
    // sort by `order`
    did_configs.sort_by(|(_, fields1), (_, fields2)| fields1.order.cmp(&fields2.order));

    let mut did_methods: IndexMap<String, Arc<dyn DidMethod>> = IndexMap::new();
    let mut did_webvh_params: Vec<(String, webvh::Params)> = vec![];

    for (name, field) in did_configs {
        let did_method: Arc<dyn DidMethod> = match field.r#type {
            DidType::Key => Arc::new(KeyDidMethod::new(key_algorithm_provider.clone())),
            DidType::Web => {
                let params: web::Params = config.did.get(name)?;
                let did_web = WebDidMethod::new(&core_base_url, client.clone(), params)
                    .map_err(|_| ConfigValidationError::EntryNotFound("Base url".to_string()))?;
                Arc::new(did_web)
            }
            DidType::Jwk => Arc::new(JWKDidMethod::new(key_algorithm_provider.clone())),
            DidType::Universal => {
                let params: universal::Params = config.did.get(name)?;
                Arc::new(UniversalDidMethod::new(params, client.clone()))
            }
            DidType::WebVh => {
                let params: webvh::Params = config.did.get(name)?;
                // did:webvh cannot be constructed yet, as it needs a did resolver internally
                // -> save for later
                did_webvh_params.push((name.to_string(), params));
                continue;
            }
        };
        did_methods.insert(name.to_owned(), did_method);
    }

    let did_caching_loader = initialize_did_caching_loader(
        &config.cache_entities,
        remote_entity_cache_repository.clone(),
    );
    let intermediary_provider = Arc::new(DidMethodProviderImpl::new(
        did_caching_loader,
        did_methods.clone(),
    ));

    // Separately construct the did:webvh providers using the intermediary provider
    for (name, params) in did_webvh_params {
        let did_webvh = webvh::DidWebVh::new(
            params,
            core_base_url.clone(),
            client.clone(),
            intermediary_provider.clone(),
            Some(key_provider.clone()),
        );
        did_methods.insert(name, Arc::new(did_webvh));
    }

    for (key, value) in config.did.iter_mut() {
        if let Some(entity) = did_methods.get(key) {
            let params = entity.get_keys().map(|keys| core_config::Params {
                public: Some(json!({
                    "keys": keys,
                })),
                private: None,
            });

            *value = Fields {
                capabilities: Some(json!(entity.get_capabilities())),
                params,
                ..value.clone()
            }
        }
    }

    let did_caching_loader =
        initialize_did_caching_loader(&config.cache_entities, remote_entity_cache_repository);
    Ok(Arc::new(DidMethodProviderImpl::new(
        did_caching_loader,
        did_methods,
    )))
}

fn initialize_did_caching_loader(
    cache_entities_config: &CacheEntitiesConfig,
    remote_entity_cache_repository: Arc<dyn RemoteEntityCacheRepository>,
) -> DidCachingLoader {
    let config = cache_entities_config
        .entities
        .get("DID_DOCUMENT")
        .cloned()
        .unwrap_or(CacheEntityConfig {
            cache_refresh_timeout: Duration::days(1),
            cache_size: 100,
            cache_type: CacheEntityCacheType::Db,
            refresh_after: Duration::minutes(5),
        });

    let storage: Arc<dyn RemoteEntityStorage> = match config.cache_type {
        CacheEntityCacheType::Db => Arc::new(DbStorage::new(remote_entity_cache_repository)),
        CacheEntityCacheType::InMemory => Arc::new(InMemoryStorage::new(HashMap::new())),
    };

    DidCachingLoader::new(
        RemoteEntityType::DidDocument,
        storage,
        config.cache_size as usize,
        config.cache_refresh_timeout,
        config.refresh_after,
    )
}

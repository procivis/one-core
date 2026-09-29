//! DID method provider.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::json;
use shared_types::{DidMethodId, DidValue};

use super::DidMethod;
use super::decorators::CapabilityChecked;
use super::dto::DidDocumentDTO;
use super::error::DidMethodProviderError;
use super::jwk::JWKDidMethod;
use super::key::KeyDidMethod;
use super::model::DidDocument;
use super::resolver::{DidCachingLoader, DidResolver};
use super::tdw::DidTdw;
use super::universal::UniversalDidMethod;
use super::web::WebDidMethod;
use super::webvh::DidWebvh;
use crate::config::ConfigValidationError;
use crate::config::core_config::{
    self, CacheEntitiesConfig, CacheEntityCacheType, CoreConfig, DidType, Fields,
};
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt, NestedError};
use crate::proto::http_client::HttpClient;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::provider_directory::{InitializationError, ProviderDirectory};
use crate::provider::remote_entity_storage::db_storage::DbStorage;
use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
use crate::provider::remote_entity_storage::{RemoteEntityStorage, RemoteEntityType};
use crate::repository::remote_entity_cache_repository::RemoteEntityCacheRepository;
use crate::service::error::ServiceError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait DidMethodProvider: Send + Sync {
    fn get_did_method(
        &self,
        did_method_id: &DidMethodId,
    ) -> Result<(Arc<dyn DidMethod>, DidType), NestedError>;

    fn get_did_method_id(&self, did: &DidValue) -> Result<DidMethodId, DidMethodProviderError>;

    fn get_did_method_by_method_name(
        &self,
        method_name: &str,
    ) -> Result<(DidMethodId, Arc<dyn DidMethod>), DidMethodProviderError>;

    async fn resolve(&self, did: &DidValue) -> Result<DidDocument, DidMethodProviderError>;

    fn supported_method_names(&self) -> Vec<String>;
}

struct DidMethodProviderImpl {
    caching_loader: DidCachingLoader,
    directory: ProviderDirectory<DidMethodId, Fields<DidType>, dyn DidMethod>,
    resolver: Arc<DidResolver>,
}

impl DidMethodProviderImpl {
    fn new(
        caching_loader: DidCachingLoader,
        directory: ProviderDirectory<DidMethodId, Fields<DidType>, dyn DidMethod>,
    ) -> Self {
        let resolver = DidResolver {
            directory: directory.clone(),
        };

        Self {
            caching_loader,
            directory,
            resolver: Arc::new(resolver),
        }
    }
}

#[async_trait::async_trait]
impl DidMethodProvider for DidMethodProviderImpl {
    fn get_did_method(
        &self,
        did_method_id: &DidMethodId,
    ) -> Result<(Arc<dyn DidMethod>, DidType), NestedError> {
        let provider = self.directory.provider(did_method_id)?;
        let config = self.directory.config(did_method_id)?;
        Ok((provider, config.r#type))
    }

    fn get_did_method_id(&self, did: &DidValue) -> Result<DidMethodId, DidMethodProviderError> {
        let did_method = did.method();
        self.directory
            .iter()
            .find(|(_, method)| {
                method
                    .get_capabilities()
                    .method_names
                    .iter()
                    .any(|v| v == did_method)
            })
            .map(|(id, _)| id.clone())
            .ok_or_else(|| DidMethodProviderError::UnknownDidMethod(did_method.to_string()))
    }

    fn get_did_method_by_method_name(
        &self,
        method_name: &str,
    ) -> Result<(DidMethodId, Arc<dyn DidMethod>), DidMethodProviderError> {
        self.directory
            .iter()
            .find(|(_, method)| {
                method
                    .get_capabilities()
                    .method_names
                    .contains(&method_name.to_string())
            })
            .map(|(id, method)| (id.clone(), method.clone()))
            .ok_or_else(|| DidMethodProviderError::UnknownDidMethod(method_name.to_string()))
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
        self.directory
            .iter()
            .flat_map(|(_, did_method)| did_method.get_capabilities().method_names)
            .collect()
    }
}

fn initialize_independent_provider(
    name: &DidMethodId,
    fields: &Fields<DidType>,
    core_base_url: &Option<String>,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    client: &Arc<dyn HttpClient>,
) -> Result<Arc<dyn DidMethod>, InitializationError> {
    let provider: Arc<dyn DidMethod> = match fields.r#type {
        DidType::Key => Arc::new(KeyDidMethod::new(
            name.to_owned(),
            key_algorithm_provider.clone(),
        )),
        DidType::Web => {
            let did_web = WebDidMethod::new(
                name.to_owned(),
                core_base_url,
                client.clone(),
                fields.merge_fields(),
            )
            .error_while(format!("initalizing DID web: `{name}`"))?;
            Arc::new(did_web)
        }
        DidType::Jwk => Arc::new(JWKDidMethod::new(
            name.to_owned(),
            key_algorithm_provider.clone(),
        )),
        DidType::Universal => Arc::new(UniversalDidMethod::new(
            name.to_owned(),
            fields.merge_fields(),
            client.clone(),
        )?),
        DidType::Tdw | DidType::Webvh => {
            return Err(
                ServiceError::MappingError("Invalid initialization".to_string())
                    .error_while("initializing dependent DID provider")
                    .into(),
            );
        }
    };
    Ok(Arc::new(CapabilityChecked(provider)))
}

fn initialize_dependent_provider(
    name: &DidMethodId,
    fields: &Fields<DidType>,
    core_base_url: &Option<String>,
    intermediary_provider: &Arc<dyn DidMethodProvider>,
    key_provider: &Arc<dyn KeyProvider>,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    client: &Arc<dyn HttpClient>,
) -> Result<Arc<dyn DidMethod>, InitializationError> {
    let method: Arc<dyn DidMethod> = match fields.r#type {
        DidType::Tdw => Arc::new(DidTdw::new(
            name.to_owned(),
            fields.merge_fields(),
            core_base_url.clone(),
            client.clone(),
            intermediary_provider.clone(),
            key_provider.clone(),
        )?),
        DidType::Webvh => Arc::new(DidWebvh::new(
            name.to_owned(),
            fields.merge_fields(),
            core_base_url.clone(),
            client.clone(),
            intermediary_provider.clone(),
            key_provider.clone(),
            key_algorithm_provider.clone(),
        )?),
        _ => {
            return Err(
                ServiceError::MappingError("Invalid dependent DID type".to_string())
                    .error_while("initializing dependent DID provider")
                    .into(),
            );
        }
    };
    Ok(Arc::new(CapabilityChecked(method)))
}

pub(crate) fn did_method_provider_from_config(
    config: &mut CoreConfig,
    core_base_url: Option<String>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    key_provider: Arc<dyn KeyProvider>,
    client: Arc<dyn HttpClient>,
    remote_entity_cache_repository: Arc<dyn RemoteEntityCacheRepository>,
) -> Result<Arc<dyn DidMethodProvider>, ConfigValidationError> {
    // did:tdw and did:webvh depend on did:key to verify their update proofs.
    let directory = {
        let (dependent_methods, independent_methods): (Vec<_>, Vec<_>) = config
            .did
            .iter_mut()
            .partition(|(_, entry)| matches!(entry.r#type, DidType::Tdw | DidType::Webvh));

        let independent_directory = ProviderDirectory::initialize(
            independent_methods.into_iter(),
            |name: &DidMethodId, fields: &Fields<DidType>| {
                initialize_independent_provider(
                    name,
                    fields,
                    &core_base_url,
                    &key_algorithm_provider,
                    &client,
                )
            },
        )
        .error_while("initializing DID providers")?;

        let did_caching_loader = initialize_did_caching_loader(
            &config.cache_entities,
            remote_entity_cache_repository.clone(),
        );
        let intermediary_provider: Arc<dyn DidMethodProvider> = Arc::new(
            DidMethodProviderImpl::new(did_caching_loader, independent_directory.clone()),
        );

        let mut directory = ProviderDirectory::initialize(
            dependent_methods.into_iter(),
            |name: &DidMethodId, fields: &Fields<DidType>| {
                initialize_dependent_provider(
                    name,
                    fields,
                    &core_base_url,
                    &intermediary_provider,
                    &key_provider,
                    &key_algorithm_provider,
                    &client,
                )
            },
        )
        .error_while("initializing dependent DID providers")?;

        directory.merge(independent_directory);
        directory
    };

    for (key, fields) in config.did.iter_mut() {
        let method = directory.provider(key)?;
        fields.params = method.get_keys().map(|keys| core_config::Params {
            public: Some(json!({ "keys": keys })),
            private: None,
        });
    }

    let did_caching_loader =
        initialize_did_caching_loader(&config.cache_entities, remote_entity_cache_repository);
    Ok(Arc::new(DidMethodProviderImpl::new(
        did_caching_loader,
        directory,
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
        .unwrap_or_default();

    let storage: Arc<dyn RemoteEntityStorage> = match config.cache_type {
        CacheEntityCacheType::Db => Arc::new(DbStorage::new(remote_entity_cache_repository)),
        CacheEntityCacheType::InMemory => Arc::new(InMemoryStorage::new(HashMap::new())),
    };

    DidCachingLoader::new(
        RemoteEntityType::DidDocument,
        storage,
        config.cache_size as usize,
        config.cache_refresh_timeout_seconds,
        config.refresh_after_seconds,
    )
}

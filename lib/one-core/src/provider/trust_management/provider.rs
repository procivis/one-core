use std::collections::HashMap;
use std::sync::Arc;

use serde_json::json;
use time::Duration;

use super::simple_list::SimpleList;
use super::{TrustManagement, simple_list};
use crate::config::ConfigValidationError;
use crate::config::core_config::{
    CacheEntityCacheType, CacheEntityConfig, ConfigFields, CoreConfig, TrustManagementType,
};
use crate::model::credential::Credential;
use crate::model::interaction::Interaction;
use crate::model::trust_entity::TrustEntityRole;
use crate::proto::http_client::HttpClient;
use crate::provider::caching_loader::trust_list::{TrustListCache, TrustListResolver};
use crate::provider::remote_entity_storage::RemoteEntityStorage;
use crate::provider::remote_entity_storage::db_storage::DbStorage;
use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
use crate::repository::remote_entity_cache_repository::RemoteEntityCacheRepository;

#[cfg_attr(test, mockall::automock)]
pub trait TrustManagementProvider: Send + Sync {
    fn get(&self, name: &str) -> Option<Arc<dyn TrustManagement>>;
    fn get_by_credential(&self, credential: &Credential) -> Option<Arc<dyn TrustManagement>>;
    fn get_by_interaction(
        &self,
        interaction: &Interaction,
        role: &TrustEntityRole,
    ) -> Option<Arc<dyn TrustManagement>>;
}

struct TrustManagementProviderImpl {
    trust_managers: HashMap<String, Arc<dyn TrustManagement>>,
}

impl TrustManagementProvider for TrustManagementProviderImpl {
    fn get(&self, name: &str) -> Option<Arc<dyn TrustManagement>> {
        self.trust_managers.get(name).cloned()
    }

    fn get_by_credential(&self, _credential: &Credential) -> Option<Arc<dyn TrustManagement>> {
        unimplemented!()
    }

    fn get_by_interaction(
        &self,
        _interaction: &Interaction,
        _role: &TrustEntityRole,
    ) -> Option<Arc<dyn TrustManagement>> {
        unimplemented!()
    }
}

pub(crate) fn trust_management_provider_from_config(
    config: &mut CoreConfig,
    client: Arc<dyn HttpClient>,
    remote_entity_cache_repository: Arc<dyn RemoteEntityCacheRepository>,
) -> Result<Arc<dyn TrustManagementProvider>, ConfigValidationError> {
    let mut trust_managers: HashMap<String, Arc<dyn TrustManagement>> = HashMap::new();

    let trust_list_cache = Arc::new(initialize_trust_list_cache(
        config,
        remote_entity_cache_repository,
        client.clone(),
    ));

    for (key, fields) in config.trust_management.iter() {
        if !fields.enabled() {
            continue;
        }

        let management = match fields.r#type {
            TrustManagementType::SimpleTrustList => {
                let params: simple_list::Params = config.trust_management.get(key)?;
                Arc::new(SimpleList {
                    params,
                    client: client.clone(),
                    trust_list_cache: trust_list_cache.clone(),
                }) as _
            }
        };

        trust_managers.insert(key.to_string(), management);
    }

    for (key, value) in config.trust_management.iter_mut() {
        if let Some(entity) = trust_managers.get(key) {
            value.capabilities = Some(json!(entity.get_capabilities()));
        }
    }

    Ok(Arc::new(TrustManagementProviderImpl { trust_managers }))
}

fn initialize_trust_list_cache(
    config: &CoreConfig,
    remote_entity_cache_repository: Arc<dyn RemoteEntityCacheRepository>,
    client: Arc<dyn HttpClient>,
) -> TrustListCache {
    let config = config
        .cache_entities
        .entities
        .get("TRUST_LIST")
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

    TrustListCache::new(
        Arc::new(TrustListResolver::new(client)),
        storage,
        config.cache_size as usize,
        config.cache_refresh_timeout,
        config.refresh_after,
    )
}

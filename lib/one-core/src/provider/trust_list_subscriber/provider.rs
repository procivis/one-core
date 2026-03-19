use std::collections::HashMap;
use std::sync::Arc;

use serde_json::json;
use shared_types::TrustListSubscriberId;
use time::Duration;

use crate::config::ConfigValidationError;
use crate::config::core_config::{
    CacheEntityCacheType, CacheEntityConfig, CoreConfig, TrustListSubscriberType,
};
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::clock::Clock;
use crate::proto::http_client::HttpClient;
use crate::provider::caching_loader::etsi_lote::EtsiLoteCache;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::remote_entity_storage::RemoteEntityStorage;
use crate::provider::remote_entity_storage::db_storage::DbStorage;
use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
use crate::provider::trust_list_subscriber::TrustListSubscriber;
use crate::provider::trust_list_subscriber::etsi_lote::resolver::EtsiLoteResolver;
use crate::provider::trust_list_subscriber::etsi_lote::{EtsiLoteParams, EtsiLoteSubscriber};
use crate::repository::remote_entity_cache_repository::RemoteEntityCacheRepository;

#[cfg_attr(test, mockall::automock)]
pub trait TrustListSubscriberProvider: Send + Sync {
    fn get(&self, subscriber_id: &TrustListSubscriberId) -> Option<Arc<dyn TrustListSubscriber>>;
}

struct TrustListSubscriberProviderImpl {
    subscribers: HashMap<TrustListSubscriberId, Arc<dyn TrustListSubscriber>>,
}

impl TrustListSubscriberProvider for TrustListSubscriberProviderImpl {
    fn get(&self, subscriber_id: &TrustListSubscriberId) -> Option<Arc<dyn TrustListSubscriber>> {
        self.subscribers.get(subscriber_id).cloned()
    }
}

pub(crate) fn trust_list_subscriber_provider_from_config(
    config: &mut CoreConfig,
    clock: Arc<dyn Clock>,
    client: Arc<dyn HttpClient>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    remote_entity_cache_repository: Arc<dyn RemoteEntityCacheRepository>,
) -> Result<Arc<dyn TrustListSubscriberProvider>, ConfigValidationError> {
    let mut subscribers: HashMap<TrustListSubscriberId, Arc<dyn TrustListSubscriber>> =
        HashMap::new();

    for (key, fields) in config.trust_list_subscriber.iter() {
        if !fields.enabled {
            continue;
        }
        let subscriber: Arc<dyn TrustListSubscriber> = match fields.r#type {
            TrustListSubscriberType::EtsiLote => {
                let params: EtsiLoteParams = config.trust_list_subscriber.get(key)?;
                let resolver = EtsiLoteResolver::new(
                    clock.clone(),
                    client.clone(),
                    did_method_provider.clone(),
                    key_algorithm_provider.clone(),
                    certificate_validator.clone(),
                    params.accepts,
                    params.leeway,
                );
                let etsi_lote_cache = initialize_etsi_lote_cache(
                    config,
                    remote_entity_cache_repository.clone(),
                    resolver,
                );
                Arc::new(EtsiLoteSubscriber::new(etsi_lote_cache)) as _
            }
        };
        subscribers.insert(key.clone(), subscriber);
    }

    for (key, value) in config.trust_list_subscriber.iter_mut() {
        if let Some(entity) = subscribers.get(key) {
            value.capabilities = Some(json!(entity.get_capabilities()));
        }
    }

    Ok(Arc::new(TrustListSubscriberProviderImpl { subscribers }))
}

fn initialize_etsi_lote_cache(
    config: &CoreConfig,
    remote_entity_cache_repository: Arc<dyn RemoteEntityCacheRepository>,
    resolver: EtsiLoteResolver,
) -> EtsiLoteCache {
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
    EtsiLoteCache::new(
        Arc::new(resolver),
        storage,
        config.cache_size as usize,
        config.cache_refresh_timeout,
        config.refresh_after,
    )
}

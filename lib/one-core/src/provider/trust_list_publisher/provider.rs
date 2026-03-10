use std::collections::HashMap;
use std::sync::Arc;

use serde_json::json;
use shared_types::TrustListPublisherId;

use super::TrustListPublisher;
use super::etsi_lote::{EtsiLoteParams, EtsiLotePublisher};
use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, TrustListPublisherType};
use crate::proto::clock::Clock;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::trust_entry_repository::TrustEntryRepository;
use crate::repository::trust_list_publication_repository::TrustListPublicationRepository;

#[cfg_attr(test, mockall::automock)]
pub trait TrustListPublisherProvider: Send + Sync {
    fn get(&self, trust_list_id: &TrustListPublisherId) -> Option<Arc<dyn TrustListPublisher>>;
}

struct TrustListPublisherProviderImpl {
    publishers: HashMap<TrustListPublisherId, Arc<dyn TrustListPublisher>>,
}

impl TrustListPublisherProvider for TrustListPublisherProviderImpl {
    fn get(&self, trust_list_id: &TrustListPublisherId) -> Option<Arc<dyn TrustListPublisher>> {
        self.publishers.get(trust_list_id).cloned()
    }
}

pub(crate) fn trust_list_publisher_provider_from_config(
    config: &mut CoreConfig,
    clock: Arc<dyn Clock>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    trust_list_publication_repository: Arc<dyn TrustListPublicationRepository>,
    trust_entry_repository: Arc<dyn TrustEntryRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
) -> Result<Arc<dyn TrustListPublisherProvider>, ConfigValidationError> {
    let mut publishers: HashMap<TrustListPublisherId, Arc<dyn TrustListPublisher>> = HashMap::new();

    for (key, fields) in config.trust_list_publisher.iter() {
        if !fields.enabled {
            continue;
        }
        let method_id: TrustListPublisherId = key.as_str().into();
        let publisher: Arc<dyn TrustListPublisher> = match fields.r#type {
            TrustListPublisherType::EtsiLote => {
                let params: EtsiLoteParams = config.trust_list_publisher.get(key)?;
                Arc::new(EtsiLotePublisher {
                    method_id: method_id.clone(),
                    params,
                    clock: clock.clone(),
                    key_provider: key_provider.clone(),
                    key_algorithm_provider: key_algorithm_provider.clone(),
                    trust_list_publication_repository: trust_list_publication_repository.clone(),
                    trust_entry_repository: trust_entry_repository.clone(),
                    identifier_repository: identifier_repository.clone(),
                }) as _
            }
        };
        publishers.insert(method_id, publisher);
    }

    for (key, value) in config.trust_list_publisher.iter_mut() {
        let method_id: TrustListPublisherId = key.as_str().into();
        if let Some(entity) = publishers.get(&method_id) {
            value.capabilities = Some(json!(entity.get_capabilities()));
        }
    }

    Ok(Arc::new(TrustListPublisherProviderImpl { publishers }))
}

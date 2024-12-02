use std::sync::Arc;

use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::http_client::HttpClient;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::trust_management::provider::TrustManagementProvider;
use crate::repository::did_repository::DidRepository;
use crate::repository::trust_anchor_repository::TrustAnchorRepository;
use crate::repository::trust_entity_repository::TrustEntityRepository;

pub mod dto;
pub mod mapper;
pub mod service;

#[derive(Clone)]
pub struct TrustEntityService {
    trust_anchor_repository: Arc<dyn TrustAnchorRepository>,
    trust_entity_repository: Arc<dyn TrustEntityRepository>,
    did_repository: Arc<dyn DidRepository>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    trust_provider: Arc<dyn TrustManagementProvider>,
    key_provider: Arc<dyn KeyProvider>,
    client: Arc<dyn HttpClient>,
}

impl TrustEntityService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        trust_anchor_repository: Arc<dyn TrustAnchorRepository>,
        trust_entity_repository: Arc<dyn TrustEntityRepository>,
        did_repository: Arc<dyn DidRepository>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        trust_provider: Arc<dyn TrustManagementProvider>,
        key_provider: Arc<dyn KeyProvider>,
        client: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            trust_anchor_repository,
            trust_entity_repository,
            did_repository,
            did_method_provider,
            key_algorithm_provider,
            trust_provider,
            key_provider,
            client,
        }
    }
}

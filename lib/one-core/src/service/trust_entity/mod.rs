use std::sync::Arc;

use crate::provider::trust_management::provider::TrustManagementProvider;
use crate::repository::trust_anchor_repository::TrustAnchorRepository;
use crate::repository::trust_entity_repository::TrustEntityRepository;

pub mod dto;
pub mod mapper;
pub mod service;

#[derive(Clone)]
pub struct TrustEntityService {
    trust_anchor_repository: Arc<dyn TrustAnchorRepository>,
    trust_entity_repository: Arc<dyn TrustEntityRepository>,
    trust_provider: Arc<dyn TrustManagementProvider>,
}

impl TrustEntityService {
    pub fn new(
        trust_anchor_repository: Arc<dyn TrustAnchorRepository>,
        trust_entity_repository: Arc<dyn TrustEntityRepository>,
        trust_provider: Arc<dyn TrustManagementProvider>,
    ) -> Self {
        Self {
            trust_anchor_repository,
            trust_entity_repository,
            trust_provider,
        }
    }
}

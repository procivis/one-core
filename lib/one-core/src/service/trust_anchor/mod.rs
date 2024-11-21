use std::sync::Arc;

use crate::config::core_config;
use crate::repository::trust_anchor_repository::TrustAnchorRepository;
use crate::repository::trust_entity_repository::TrustEntityRepository;

pub mod dto;
pub mod mapper;
pub mod service;

#[derive(Clone)]
pub struct TrustAnchorService {
    trust_anchor_repository: Arc<dyn TrustAnchorRepository>,
    trust_entity_repository: Arc<dyn TrustEntityRepository>,
    config: Arc<core_config::CoreConfig>,
    core_base_url: Option<String>,
}

impl TrustAnchorService {
    pub fn new(
        trust_anchor_repository: Arc<dyn TrustAnchorRepository>,
        trust_entity_repository: Arc<dyn TrustEntityRepository>,
        core_base_url: Option<String>,
        config: Arc<core_config::CoreConfig>,
    ) -> Self {
        Self {
            trust_anchor_repository,
            trust_entity_repository,
            core_base_url,
            config,
        }
    }
}

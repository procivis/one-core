use std::sync::Arc;

use crate::config::core_config;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::trust_anchor_repository::TrustAnchorRepository;
use crate::repository::trust_entity_repository::TrustEntityRepository;

pub mod dto;
pub mod mapper;
pub mod service;

#[derive(Clone)]
pub struct TrustAnchorService {
    trust_anchor_repository: Arc<dyn TrustAnchorRepository>,
    trust_entity_repository: Arc<dyn TrustEntityRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    config: Arc<core_config::CoreConfig>,
    core_base_url: Option<String>,
}

impl TrustAnchorService {
    pub fn new(
        trust_anchor_repository: Arc<dyn TrustAnchorRepository>,
        trust_entity_repository: Arc<dyn TrustEntityRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        core_base_url: Option<String>,
        config: Arc<core_config::CoreConfig>,
    ) -> Self {
        Self {
            trust_anchor_repository,
            trust_entity_repository,
            history_repository,
            organisation_repository,
            core_base_url,
            config,
        }
    }
}

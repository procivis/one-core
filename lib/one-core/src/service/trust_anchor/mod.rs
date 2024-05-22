use std::sync::Arc;

use crate::{
    config::core_config,
    repository::{
        history_repository::HistoryRepository, trust_anchor_repository::TrustAnchorRepository,
        trust_entity_repository::TrustEntityRepository,
    },
};

pub mod dto;
pub mod mapper;
pub mod service;

#[derive(Clone)]
pub struct TrustAnchorService {
    trust_anchor_repository: Arc<dyn TrustAnchorRepository>,
    trust_entity_repository: Arc<dyn TrustEntityRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    config: Arc<core_config::CoreConfig>,
}

impl TrustAnchorService {
    pub fn new(
        trust_anchor_repository: Arc<dyn TrustAnchorRepository>,
        trust_entity_repository: Arc<dyn TrustEntityRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        config: Arc<core_config::CoreConfig>,
    ) -> Self {
        Self {
            trust_anchor_repository,
            trust_entity_repository,
            history_repository,
            config,
        }
    }
}

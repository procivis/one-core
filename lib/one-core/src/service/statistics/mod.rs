use std::sync::Arc;

use crate::proto::session_provider::SessionProvider;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::organisation_repository::OrganisationRepository;

pub mod dto;
pub mod error;
mod mapper;
pub mod service;

pub struct StatisticsService {
    history_repository: Arc<dyn HistoryRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    session_provider: Arc<dyn SessionProvider>,
}

impl StatisticsService {
    pub fn new(
        history_repository: Arc<dyn HistoryRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        session_provider: Arc<dyn SessionProvider>,
    ) -> Self {
        Self {
            history_repository,
            organisation_repository,
            session_provider,
        }
    }
}

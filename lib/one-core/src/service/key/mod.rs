use std::sync::Arc;

use crate::config::core_config;
use crate::proto::csr_creator::CsrCreator;
use crate::proto::session_provider::SessionProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::organisation_repository::OrganisationRepository;

pub mod dto;
pub mod error;
pub mod service;

pub(crate) mod mapper;
pub(crate) mod validator;

#[derive(Clone)]
pub struct KeyService {
    key_repository: Arc<dyn KeyRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    key_provider: Arc<dyn KeyProvider>,
    config: Arc<core_config::CoreConfig>,
    history_repository: Arc<dyn HistoryRepository>,
    session_provider: Arc<dyn SessionProvider>,
    csr_creator: Arc<dyn CsrCreator>,
}

impl KeyService {
    pub fn new(
        key_repository: Arc<dyn KeyRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        key_provider: Arc<dyn KeyProvider>,
        config: Arc<core_config::CoreConfig>,
        history_repository: Arc<dyn HistoryRepository>,
        session_provider: Arc<dyn SessionProvider>,
        csr_creator: Arc<dyn CsrCreator>,
    ) -> Self {
        Self {
            key_repository,
            organisation_repository,
            key_provider,
            config,
            history_repository,
            session_provider,
            csr_creator,
        }
    }
}

#[cfg(test)]
mod test;

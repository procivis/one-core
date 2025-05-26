use std::sync::Arc;

use crate::config::core_config;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::organisation_repository::OrganisationRepository;

pub mod dto;
pub mod service;

pub(crate) mod mapper;
pub(crate) mod validator;

#[derive(Clone)]
pub struct KeyService {
    key_repository: Arc<dyn KeyRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    key_provider: Arc<dyn KeyProvider>,
    config: Arc<core_config::CoreConfig>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    history_repository: Arc<dyn HistoryRepository>,
}

impl KeyService {
    pub fn new(
        key_repository: Arc<dyn KeyRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        key_provider: Arc<dyn KeyProvider>,
        config: Arc<core_config::CoreConfig>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        history_repository: Arc<dyn HistoryRepository>,
    ) -> Self {
        Self {
            key_repository,
            organisation_repository,
            key_provider,
            config,
            key_algorithm_provider,
            history_repository,
        }
    }
}

#[cfg(test)]
mod test;

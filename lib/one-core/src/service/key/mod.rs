use std::sync::Arc;

use one_providers::key_algorithm::provider::KeyAlgorithmProvider;
use one_providers::key_storage::provider::KeyProvider;

use crate::config::core_config;
use crate::provider::did_method::mdl::DidMdlValidator;
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
    history_repository: Arc<dyn HistoryRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    did_mdl_validator: Arc<dyn DidMdlValidator>,
    key_provider: Arc<dyn KeyProvider>,
    config: Arc<core_config::CoreConfig>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
}

impl KeyService {
    pub fn new(
        key_repository: Arc<dyn KeyRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        did_mdl_validator: Arc<dyn DidMdlValidator>,
        key_provider: Arc<dyn KeyProvider>,
        config: Arc<core_config::CoreConfig>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    ) -> Self {
        Self {
            key_repository,
            history_repository,
            organisation_repository,
            did_mdl_validator,
            key_provider,
            config,
            key_algorithm_provider,
        }
    }
}

#[cfg(test)]
mod test;

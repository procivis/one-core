use std::sync::Arc;

use crate::key_storage::provider::KeyProvider;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::{config::data_structure::CoreConfig, repository::key_repository::KeyRepository};

pub mod service;

pub mod dto;

pub(crate) mod mapper;
pub(crate) mod validator;

#[derive(Clone)]
pub struct KeyService {
    key_repository: Arc<dyn KeyRepository + Send + Sync>,
    organisation_repository: Arc<dyn OrganisationRepository + Send + Sync>,
    key_provider: Arc<dyn KeyProvider + Send + Sync>,
    _config: Arc<CoreConfig>,
}

impl KeyService {
    pub fn new(
        key_repository: Arc<dyn KeyRepository + Send + Sync>,
        organisation_repository: Arc<dyn OrganisationRepository + Send + Sync>,
        key_provider: Arc<dyn KeyProvider + Send + Sync>,
        config: Arc<CoreConfig>,
    ) -> Self {
        Self {
            key_repository,
            organisation_repository,
            key_provider,
            _config: config,
        }
    }
}

#[cfg(test)]
mod test;

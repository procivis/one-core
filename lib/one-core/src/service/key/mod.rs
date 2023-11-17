use std::sync::Arc;

use crate::provider::key_storage::provider::KeyProvider;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::{config::data_structure::CoreConfig, repository::key_repository::KeyRepository};

pub mod dto;
pub mod service;

pub(crate) mod mapper;
pub(crate) mod validator;

#[derive(Clone)]
pub struct KeyService {
    key_repository: Arc<dyn KeyRepository + Send + Sync>,
    organisation_repository: Arc<dyn OrganisationRepository + Send + Sync>,
    key_provider: Arc<dyn KeyProvider + Send + Sync>,
    config: Arc<CoreConfig>,
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
            config,
        }
    }
}

#[cfg(test)]
mod test;

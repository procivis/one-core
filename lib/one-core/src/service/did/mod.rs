use std::sync::Arc;

use crate::{
    config::core_config,
    provider::did_method::provider::DidMethodProvider,
    repository::{
        did_repository::DidRepository, key_repository::KeyRepository,
        organisation_repository::OrganisationRepository,
    },
};

pub mod service;

pub mod dto;

pub(crate) mod mapper;
pub(crate) mod validator;

#[derive(Clone)]
pub struct DidService {
    did_repository: Arc<dyn DidRepository + Send + Sync>,
    key_repository: Arc<dyn KeyRepository + Send + Sync>,
    organisation_repository: Arc<dyn OrganisationRepository + Send + Sync>,
    did_method_provider: Arc<dyn DidMethodProvider + Send + Sync>,
    config: Arc<core_config::CoreConfig>,
}

impl DidService {
    pub fn new(
        did_repository: Arc<dyn DidRepository + Send + Sync>,
        key_repository: Arc<dyn KeyRepository + Send + Sync>,
        organisation_repository: Arc<dyn OrganisationRepository + Send + Sync>,
        did_method_provider: Arc<dyn DidMethodProvider + Send + Sync>,
        config: Arc<core_config::CoreConfig>,
    ) -> Self {
        Self {
            did_repository,
            key_repository,
            organisation_repository,
            did_method_provider,
            config,
        }
    }
}

#[cfg(test)]
mod test;

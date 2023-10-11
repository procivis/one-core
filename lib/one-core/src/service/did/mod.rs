use std::sync::Arc;

use crate::{
    config::data_structure::CoreConfig,
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
    organisation_repository: Arc<dyn OrganisationRepository + Send + Sync>,
    key_repository: Arc<dyn KeyRepository + Send + Sync>,
    config: Arc<CoreConfig>,
}

impl DidService {
    pub fn new(
        did_repository: Arc<dyn DidRepository + Send + Sync>,
        organisation_repository: Arc<dyn OrganisationRepository + Send + Sync>,
        key_repository: Arc<dyn KeyRepository + Send + Sync>,
        config: Arc<CoreConfig>,
    ) -> Self {
        Self {
            did_repository,
            organisation_repository,
            key_repository,
            config,
        }
    }
}

#[cfg(test)]
mod test;

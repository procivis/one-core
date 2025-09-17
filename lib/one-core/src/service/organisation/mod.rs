use std::sync::Arc;

use crate::config::core_config::CoreConfig;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::organisation_repository::OrganisationRepository;

pub mod dto;
mod mapper;
pub mod service;
#[derive(Clone)]
pub struct OrganisationService {
    organisation_repository: Arc<dyn OrganisationRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    core_config: Arc<CoreConfig>,
}

impl OrganisationService {
    pub fn new(
        organisation_repository: Arc<dyn OrganisationRepository>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        core_config: Arc<CoreConfig>,
    ) -> Self {
        Self {
            organisation_repository,
            identifier_repository,
            core_config,
        }
    }
}

#[cfg(test)]
mod test;
mod validator;

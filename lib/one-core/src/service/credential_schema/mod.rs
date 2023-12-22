pub mod dto;
pub mod mapper;
pub mod service;

pub(crate) mod validator;

use std::sync::Arc;

use crate::config::core_config;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::organisation_repository::OrganisationRepository;

#[derive(Clone)]
pub struct CredentialSchemaService {
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    config: Arc<core_config::CoreConfig>,
}

impl CredentialSchemaService {
    pub fn new(
        repository: Arc<dyn CredentialSchemaRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        config: Arc<core_config::CoreConfig>,
    ) -> Self {
        Self {
            credential_schema_repository: repository,
            organisation_repository,
            config,
        }
    }
}

#[cfg(test)]
mod test;

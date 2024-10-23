use std::sync::Arc;

use crate::config::core_config;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;

pub mod dto;
mod mapper;
pub mod service;

#[cfg(test)]
mod test;

#[derive(Clone)]
pub struct SSIIssuerService {
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    config: Arc<core_config::CoreConfig>,
    core_base_url: Option<String>,
}

impl SSIIssuerService {
    pub(crate) fn new(
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        config: Arc<core_config::CoreConfig>,
        core_base_url: Option<String>,
    ) -> Self {
        Self {
            credential_schema_repository,
            config,
            core_base_url,
        }
    }
}

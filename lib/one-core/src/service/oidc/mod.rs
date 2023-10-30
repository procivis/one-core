use crate::config::data_structure::CoreConfig;
use crate::repository::credential_repository::CredentialRepository;
use std::sync::Arc;

use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::interaction_repository::InteractionRepository;

pub mod dto;
pub mod mapper;
pub mod service;

pub mod validator;
#[derive(Clone)]
pub struct OIDCService {
    pub(crate) core_base_url: Option<String>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository + Send + Sync>,
    credential_repository: Arc<dyn CredentialRepository + Send + Sync>,
    interaction_repository: Arc<dyn InteractionRepository + Send + Sync>,
    config: Arc<CoreConfig>,
}

impl OIDCService {
    pub(crate) fn new(
        core_base_url: Option<String>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository + Send + Sync>,
        credential_repository: Arc<dyn CredentialRepository + Send + Sync>,
        interaction_repository: Arc<dyn InteractionRepository + Send + Sync>,
        config: Arc<CoreConfig>,
    ) -> Self {
        Self {
            credential_schema_repository,
            credential_repository,
            interaction_repository,
            core_base_url,
            config,
        }
    }
}

#[cfg(test)]
mod test;

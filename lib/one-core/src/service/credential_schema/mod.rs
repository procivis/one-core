pub mod dto;
pub mod mapper;
pub mod service;

pub(crate) mod import;
pub(crate) mod validator;

use std::sync::Arc;

use crate::config::core_config;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::organisation_repository::OrganisationRepository;

#[derive(Clone)]
pub struct CredentialSchemaService {
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    config: Arc<core_config::CoreConfig>,
    core_base_url: Option<String>,
}

impl CredentialSchemaService {
    pub fn new(
        core_base_url: Option<String>,
        repository: Arc<dyn CredentialSchemaRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        config: Arc<core_config::CoreConfig>,
    ) -> Self {
        Self {
            credential_schema_repository: repository,
            history_repository,
            organisation_repository,
            formatter_provider,
            revocation_method_provider,
            config,
            core_base_url,
        }
    }
}

#[cfg(test)]
mod test;

use std::sync::Arc;

use crate::config::core_config;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::proof_schema_repository::ProofSchemaRepository;

pub mod dto;
pub mod service;

mod mapper;
mod validator;

#[derive(Clone)]
pub struct ProofSchemaService {
    proof_schema_repository: Arc<dyn ProofSchemaRepository>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    config: Arc<core_config::CoreConfig>,
    base_url: Option<String>,
}

impl ProofSchemaService {
    pub fn new(
        proof_schema_repository: Arc<dyn ProofSchemaRepository>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        config: Arc<core_config::CoreConfig>,
        base_url: Option<String>,
    ) -> Self {
        Self {
            proof_schema_repository,
            organisation_repository,
            history_repository,
            credential_schema_repository,
            formatter_provider,
            config,
            base_url,
        }
    }
}

#[cfg(test)]
mod test;

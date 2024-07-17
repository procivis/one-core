use std::sync::Arc;

use one_providers::credential_formatter::provider::CredentialFormatterProvider;

use crate::config::core_config;
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
    #[allow(clippy::too_many_arguments)]
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

#[derive(Debug, thiserror::Error)]
pub enum ProofSchemaImportError {
    #[error("Unsupported datatype: {0}")]
    UnsupportedDatatype(String),
    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),
    #[error("Failed getting proof schema: {0}")]
    HttpClient(#[from] reqwest::Error),
}

#[cfg(test)]
mod test;

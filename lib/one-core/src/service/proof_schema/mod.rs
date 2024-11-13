use std::sync::Arc;

use crate::config::core_config;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::http_client::HttpClient;
use crate::provider::revocation::provider::RevocationMethodProvider;
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
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    config: Arc<core_config::CoreConfig>,
    base_url: Option<String>,
    client: Arc<dyn HttpClient>,
}

impl ProofSchemaService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proof_schema_repository: Arc<dyn ProofSchemaRepository>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        config: Arc<core_config::CoreConfig>,
        base_url: Option<String>,
        client: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            proof_schema_repository,
            organisation_repository,
            history_repository,
            credential_schema_repository,
            formatter_provider,
            revocation_method_provider,
            config,
            base_url,
            client,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProofSchemaImportError {
    #[error("Unsupported datatype: {0}")]
    UnsupportedDatatype(String),
    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),
}

#[cfg(test)]
mod test;

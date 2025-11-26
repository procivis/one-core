use std::sync::Arc;

use crate::config::core_config;
use crate::proto::credential_schema::importer::CredentialSchemaImporter;
use crate::proto::credential_schema::parser::CredentialSchemaImportParser;
use crate::proto::http_client::HttpClient;
use crate::proto::session_provider::SessionProvider;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
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
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    config: Arc<core_config::CoreConfig>,
    base_url: Option<String>,
    client: Arc<dyn HttpClient>,
    session_provider: Arc<dyn SessionProvider>,
    credential_schema_import_parser: Arc<dyn CredentialSchemaImportParser>,
    credential_schema_importer: Arc<dyn CredentialSchemaImporter>,
}

impl ProofSchemaService {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        proof_schema_repository: Arc<dyn ProofSchemaRepository>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        config: Arc<core_config::CoreConfig>,
        base_url: Option<String>,
        client: Arc<dyn HttpClient>,
        session_provider: Arc<dyn SessionProvider>,
        credential_schema_import_parser: Arc<dyn CredentialSchemaImportParser>,
        credential_schema_importer: Arc<dyn CredentialSchemaImporter>,
    ) -> Self {
        Self {
            proof_schema_repository,
            organisation_repository,
            credential_schema_repository,
            formatter_provider,
            config,
            base_url,
            client,
            session_provider,
            credential_schema_import_parser,
            credential_schema_importer,
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

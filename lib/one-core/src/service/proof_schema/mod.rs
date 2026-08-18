use std::sync::Arc;

use crate::config::core_config;
use crate::proto::proof_schema::ProofSchemaImporter;
use crate::proto::session_provider::SessionProvider;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::ecosystem::directory::EcosystemDirectory;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::proof_schema_repository::ProofSchemaRepository;

pub mod dto;
pub mod error;
mod mapper;
pub mod service;
mod validator;

#[derive(Clone)]
pub struct ProofSchemaService {
    proof_schema_repository: Arc<dyn ProofSchemaRepository>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    config: Arc<core_config::CoreConfig>,
    base_url: Option<String>,
    session_provider: Arc<dyn SessionProvider>,
    proof_schema_importer: Arc<dyn ProofSchemaImporter>,
    ecosystem_provider: Arc<dyn EcosystemDirectory>,
}

impl ProofSchemaService {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        proof_schema_repository: Arc<dyn ProofSchemaRepository>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        config: Arc<core_config::CoreConfig>,
        base_url: Option<String>,
        session_provider: Arc<dyn SessionProvider>,
        proof_schema_importer: Arc<dyn ProofSchemaImporter>,
        ecosystem_provider: Arc<dyn EcosystemDirectory>,
    ) -> Self {
        Self {
            proof_schema_repository,
            organisation_repository,
            credential_schema_repository,
            formatter_provider,
            config,
            base_url,
            session_provider,
            proof_schema_importer,
            ecosystem_provider,
        }
    }
}

#[cfg(test)]
mod test;

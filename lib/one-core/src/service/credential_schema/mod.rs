pub mod dto;
pub mod mapper;
pub mod service;
pub(crate) mod validator;

use std::sync::Arc;

use crate::config::core_config;
use crate::proto::credential_schema::importer::CredentialSchemaImporter;
use crate::proto::credential_schema::parser::CredentialSchemaImportParser;
use crate::proto::session_provider::SessionProvider;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::organisation_repository::OrganisationRepository;

#[derive(Clone)]
pub struct CredentialSchemaService {
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    config: Arc<core_config::CoreConfig>,
    core_base_url: Option<String>,
    session_provider: Arc<dyn SessionProvider>,
    import_parser: Arc<dyn CredentialSchemaImportParser>,
    importer_proto: Arc<dyn CredentialSchemaImporter>,
}

impl CredentialSchemaService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        core_base_url: Option<String>,
        repository: Arc<dyn CredentialSchemaRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        config: Arc<core_config::CoreConfig>,
        session_provider: Arc<dyn SessionProvider>,
        credential_schema_import_parser: Arc<dyn CredentialSchemaImportParser>,
        credential_schema_importer: Arc<dyn CredentialSchemaImporter>,
    ) -> Self {
        Self {
            credential_schema_repository: repository,
            organisation_repository,
            formatter_provider,
            revocation_method_provider,
            config,
            core_base_url,
            session_provider,
            import_parser: credential_schema_import_parser,
            importer_proto: credential_schema_importer,
        }
    }
}

#[cfg(test)]
mod test;

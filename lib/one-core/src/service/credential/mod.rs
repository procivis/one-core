use std::sync::Arc;

use crate::config::core_config;
use crate::proto::credential_validity_manager::CredentialValidityManager;
use crate::proto::notification_scheduler::NotificationScheduler;
use crate::proto::session_provider::SessionProvider;
use crate::provider::blob_storage_provider::BlobStorageProvider;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::issuance_protocol::provider::IssuanceProtocolProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;

pub mod dto;
pub mod mapper;
pub mod service;

pub(crate) mod validator;

#[derive(Clone)]
pub struct CredentialService {
    credential_repository: Arc<dyn CredentialRepository>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    protocol_provider: Arc<dyn IssuanceProtocolProvider>,
    config: Arc<core_config::CoreConfig>,
    validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
    session_provider: Arc<dyn SessionProvider>,
    credential_validity_manager: Arc<dyn CredentialValidityManager>,
    notification_scheduler: Arc<dyn NotificationScheduler>,
}

impl CredentialService {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        repository: Arc<dyn CredentialRepository>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        protocol_provider: Arc<dyn IssuanceProtocolProvider>,
        config: Arc<core_config::CoreConfig>,
        lvvc_repository: Arc<dyn ValidityCredentialRepository>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        session_provider: Arc<dyn SessionProvider>,
        credential_validity_manager: Arc<dyn CredentialValidityManager>,
        notification_scheduler: Arc<dyn NotificationScheduler>,
    ) -> Self {
        Self {
            credential_repository: repository,
            credential_schema_repository,
            identifier_repository,
            interaction_repository,
            formatter_provider,
            protocol_provider,
            config,
            validity_credential_repository: lvvc_repository,
            blob_storage_provider,
            session_provider,
            credential_validity_manager,
            notification_scheduler,
        }
    }
}

#[cfg(test)]
mod test;

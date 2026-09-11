use std::sync::Arc;

use crate::config::core_config;
use crate::proto::credential_validity_manager::CredentialValidityManager;
use crate::proto::notification_scheduler::NotificationScheduler;
use crate::proto::session_provider::SessionProvider;
use crate::proto::transaction_manager::TransactionManager;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::ecosystem::directory::EcosystemDirectory;
use crate::provider::issuance_protocol::provider::IssuanceProtocolProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::interaction_repository::InteractionRepository;

pub mod dto;
pub mod error;
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
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
    session_provider: Arc<dyn SessionProvider>,
    credential_validity_manager: Arc<dyn CredentialValidityManager>,
    notification_scheduler: Arc<dyn NotificationScheduler>,
    tx_manager: Arc<dyn TransactionManager>,
    ecosystem_provider: Arc<dyn EcosystemDirectory>,
    history_repository: Arc<dyn HistoryRepository>,
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
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        session_provider: Arc<dyn SessionProvider>,
        credential_validity_manager: Arc<dyn CredentialValidityManager>,
        notification_scheduler: Arc<dyn NotificationScheduler>,
        tx_manager: Arc<dyn TransactionManager>,
        ecosystem_provider: Arc<dyn EcosystemDirectory>,
        history_repository: Arc<dyn HistoryRepository>,
    ) -> Self {
        Self {
            credential_repository: repository,
            credential_schema_repository,
            identifier_repository,
            interaction_repository,
            formatter_provider,
            protocol_provider,
            config,
            blob_storage_provider,
            session_provider,
            credential_validity_manager,
            notification_scheduler,
            tx_manager,
            ecosystem_provider,
            history_repository,
        }
    }
}

#[cfg(test)]
mod test;

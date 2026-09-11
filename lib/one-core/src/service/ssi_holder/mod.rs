use std::sync::Arc;

use shared_types::{EntityId, InteractionId, OrganisationId};

use crate::config::core_config;
use crate::model::ecosystem::EcosystemOutcomes;
use crate::model::history::HistoryEntityType;
use crate::proto::http_client::HttpClient;
use crate::proto::identifier_creator::IdentifierCreator;
use crate::proto::session_provider::{SessionExt, SessionProvider};
use crate::proto::transaction_manager::TransactionManager;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::ecosystem::directory::EcosystemDirectory;
use crate::provider::issuance_protocol::provider::IssuanceProtocolProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_security_level::provider::KeySecurityLevelProvider;
use crate::provider::verification_protocol::provider::VerificationProtocolProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::common_mapper::{record_ecosystems_resolved, resolved_ecosystems};

pub mod dto;
pub mod error;
pub mod issuance;
mod mapper;
pub mod service;
mod validator;
pub mod verification;

#[cfg(test)]
mod test;

#[derive(Clone)]
pub struct SSIHolderService {
    credential_repository: Arc<dyn CredentialRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    key_security_level_provider: Arc<dyn KeySecurityLevelProvider>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    issuance_protocol_provider: Arc<dyn IssuanceProtocolProvider>,
    verification_protocol_provider: Arc<dyn VerificationProtocolProvider>,
    config: Arc<core_config::CoreConfig>,
    client: Arc<dyn HttpClient>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
    session_provider: Arc<dyn SessionProvider>,
    identifier_creator: Arc<dyn IdentifierCreator>,
    transaction_manager: Arc<dyn TransactionManager>,
    ecosystem_provider: Arc<dyn EcosystemDirectory>,
    history_repository: Arc<dyn HistoryRepository>,
}

#[expect(clippy::too_many_arguments)]
impl SSIHolderService {
    pub(crate) fn new(
        credential_repository: Arc<dyn CredentialRepository>,
        proof_repository: Arc<dyn ProofRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        key_security_level_provider: Arc<dyn KeySecurityLevelProvider>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        issuance_protocol_provider: Arc<dyn IssuanceProtocolProvider>,
        verification_protocol_provider: Arc<dyn VerificationProtocolProvider>,
        config: Arc<core_config::CoreConfig>,
        client: Arc<dyn HttpClient>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        session_provider: Arc<dyn SessionProvider>,
        identifier_creator: Arc<dyn IdentifierCreator>,
        transaction_manager: Arc<dyn TransactionManager>,
        ecosystem_provider: Arc<dyn EcosystemDirectory>,
        history_repository: Arc<dyn HistoryRepository>,
    ) -> Self {
        Self {
            credential_repository,
            proof_repository,
            organisation_repository,
            interaction_repository,
            identifier_repository,
            key_algorithm_provider,
            formatter_provider,
            issuance_protocol_provider,
            verification_protocol_provider,
            config,
            client,
            blob_storage_provider,
            session_provider,
            key_security_level_provider,
            identifier_creator,
            transaction_manager,
            ecosystem_provider,
            history_repository,
        }
    }

    /// One event per entity the interaction produced. Best-effort: the interaction has already
    /// ended, so a failed write must not change its result.
    async fn record_ecosystems_resolved(
        &self,
        interaction_id: &InteractionId,
        entities: &[(EntityId, HistoryEntityType)],
    ) {
        let Some((outcomes, organisation_id)) =
            resolved_ecosystems(interaction_id, self.interaction_repository.as_ref()).await
        else {
            return;
        };

        self.write_ecosystems_resolved(&outcomes, organisation_id, entities)
            .await;
    }

    async fn write_ecosystems_resolved(
        &self,
        outcomes: &EcosystemOutcomes,
        organisation_id: OrganisationId,
        entities: &[(EntityId, HistoryEntityType)],
    ) {
        record_ecosystems_resolved(
            outcomes,
            organisation_id,
            entities,
            self.session_provider.session().user(),
            &*self.history_repository,
        )
        .await;
    }
}

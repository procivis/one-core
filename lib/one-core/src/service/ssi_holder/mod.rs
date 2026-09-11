use std::sync::Arc;

use shared_types::{EntityId, InteractionId, OrganisationId};
use uuid::Uuid;

use crate::config::core_config;
use crate::model::ecosystem::EcosystemOutcomes;
use crate::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryMetadata, HistorySource,
};
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
        let Some((outcomes, organisation_id)) = self.resolved_ecosystems(interaction_id).await
        else {
            return;
        };

        self.write_ecosystems_resolved(&outcomes, organisation_id, entities)
            .await;
    }

    /// `None` when no ecosystem was ever consulted.
    async fn resolved_ecosystems(
        &self,
        interaction_id: &InteractionId,
    ) -> Option<(EcosystemOutcomes, OrganisationId)> {
        let interaction = match self
            .interaction_repository
            .get_interaction(interaction_id, None)
            .await
        {
            Ok(interaction) => interaction,
            Err(err) => {
                tracing::warn!(%err, "failed to load interaction {interaction_id} to record the resolved ecosystems");
                return None;
            }
        };

        let outcomes = interaction.ecosystem_data.outcomes();
        if outcomes.is_empty() {
            return None;
        }

        Some((outcomes.to_owned(), interaction.organisation.id()))
    }

    async fn write_ecosystems_resolved(
        &self,
        outcomes: &EcosystemOutcomes,
        organisation_id: OrganisationId,
        entities: &[(EntityId, HistoryEntityType)],
    ) {
        for (entity_id, entity_type) in entities {
            let result = self
                .history_repository
                .create_history(History {
                    id: Uuid::new_v4().into(),
                    created_date: crate::clock::now_utc(),
                    action: HistoryAction::EcosystemsResolved,
                    name: Default::default(),
                    target: None,
                    source: HistorySource::Core,
                    entity_id: Some(*entity_id),
                    entity_type: entity_type.to_owned(),
                    metadata: Some(HistoryMetadata::EcosystemsResolved(outcomes.to_owned())),
                    organisation_id: Some(organisation_id),
                    user: self.session_provider.session().user(),
                    metadata_blob_id: None,
                })
                .await;

            if let Err(err) = result {
                tracing::warn!(%err, "failed to record the resolved ecosystems");
            }
        }
    }
}

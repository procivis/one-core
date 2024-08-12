use std::sync::Arc;

use one_providers::credential_formatter::provider::CredentialFormatterProvider;
use one_providers::did::provider::DidMethodProvider;
use one_providers::key_storage::provider::KeyProvider;

use crate::config::core_config;
use crate::provider::exchange_protocol::provider::ExchangeProtocolProviderExtra;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::proof_repository::ProofRepository;

pub mod dto;
pub mod service;

mod mapper;

#[cfg(test)]
mod test;

#[derive(Clone)]
pub struct SSIHolderService {
    credential_repository: Arc<dyn CredentialRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    did_repository: Arc<dyn DidRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    key_provider: Arc<dyn KeyProvider>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    protocol_provider: Arc<dyn ExchangeProtocolProviderExtra>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    config: Arc<core_config::CoreConfig>,
    client: reqwest::Client,
}

#[allow(clippy::too_many_arguments)]
impl SSIHolderService {
    pub(crate) fn new(
        credential_repository: Arc<dyn CredentialRepository>,
        proof_repository: Arc<dyn ProofRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        did_repository: Arc<dyn DidRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        key_provider: Arc<dyn KeyProvider>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        protocol_provider: Arc<dyn ExchangeProtocolProviderExtra>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        config: Arc<core_config::CoreConfig>,
        client: reqwest::Client,
    ) -> Self {
        Self {
            credential_repository,
            proof_repository,
            organisation_repository,
            interaction_repository,
            credential_schema_repository,
            did_repository,
            history_repository,
            key_provider,
            formatter_provider,
            protocol_provider,
            did_method_provider,
            config,
            client,
        }
    }
}

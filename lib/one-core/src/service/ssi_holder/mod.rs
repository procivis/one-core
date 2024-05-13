use crate::{
    config::core_config,
    provider::{
        credential_formatter::provider::CredentialFormatterProvider,
        did_method::provider::DidMethodProvider, key_storage::provider::KeyProvider,
        transport_protocol::provider::TransportProtocolProvider,
    },
    repository::{
        credential_repository::CredentialRepository, did_repository::DidRepository,
        history_repository::HistoryRepository, organisation_repository::OrganisationRepository,
        proof_repository::ProofRepository,
    },
};
use std::sync::Arc;

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
    did_repository: Arc<dyn DidRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    key_provider: Arc<dyn KeyProvider>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    protocol_provider: Arc<dyn TransportProtocolProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    config: Arc<core_config::CoreConfig>,
}

#[allow(clippy::too_many_arguments)]
impl SSIHolderService {
    pub(crate) fn new(
        credential_repository: Arc<dyn CredentialRepository>,
        proof_repository: Arc<dyn ProofRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        did_repository: Arc<dyn DidRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        key_provider: Arc<dyn KeyProvider>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        protocol_provider: Arc<dyn TransportProtocolProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        config: Arc<core_config::CoreConfig>,
    ) -> Self {
        Self {
            credential_repository,
            proof_repository,
            organisation_repository,
            did_repository,
            history_repository,
            key_provider,
            formatter_provider,
            protocol_provider,
            did_method_provider,
            config,
        }
    }
}

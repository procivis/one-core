use crate::config::core_config;
use crate::provider::transport_protocol::provider::TransportProtocolProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::{
    did_repository::DidRepository, interaction_repository::InteractionRepository,
    proof_repository::ProofRepository, proof_schema_repository::ProofSchemaRepository,
};
use std::sync::Arc;

pub mod dto;
mod mapper;
pub mod service;

#[allow(dead_code)] // FIXME: Remove when interaction is used
#[derive(Clone)]
pub struct ProofService {
    credential_repository: Arc<dyn CredentialRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    proof_schema_repository: Arc<dyn ProofSchemaRepository>,
    did_repository: Arc<dyn DidRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    protocol_provider: Arc<dyn TransportProtocolProvider>,
    config: Arc<core_config::CoreConfig>,
}

impl ProofService {
    pub(crate) fn new(
        credential_repository: Arc<dyn CredentialRepository>,
        proof_repository: Arc<dyn ProofRepository>,
        proof_schema_repository: Arc<dyn ProofSchemaRepository>,
        did_repository: Arc<dyn DidRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        protocol_provider: Arc<dyn TransportProtocolProvider>,
        config: Arc<core_config::CoreConfig>,
    ) -> Self {
        Self {
            credential_repository,
            proof_repository,
            proof_schema_repository,
            did_repository,
            interaction_repository,
            protocol_provider,
            config,
        }
    }
}

#[cfg(test)]
mod test;

use crate::{
    credential_formatter::provider::CredentialFormatterProvider,
    repository::{
        credential_repository::CredentialRepository,
        credential_schema_repository::CredentialSchemaRepository, did_repository::DidRepository,
        interaction_repository::InteractionRepository, proof_repository::ProofRepository,
    },
    transport_protocol::provider::TransportProtocolProvider,
};
use std::sync::Arc;

pub mod dto;
pub mod service;

mod mapper;

#[derive(Clone)]
pub struct SSIHolderService {
    credential_schema_repository: Arc<dyn CredentialSchemaRepository + Send + Sync>,
    credential_repository: Arc<dyn CredentialRepository + Send + Sync>,
    proof_repository: Arc<dyn ProofRepository + Send + Sync>,
    did_repository: Arc<dyn DidRepository + Send + Sync>,
    interaction_repository: Arc<dyn InteractionRepository + Send + Sync>,
    formatter_provider: Arc<dyn CredentialFormatterProvider + Send + Sync>,
    protocol_provider: Arc<dyn TransportProtocolProvider + Send + Sync>,
}

#[allow(clippy::too_many_arguments)]
impl SSIHolderService {
    pub(crate) fn new(
        credential_schema_repository: Arc<dyn CredentialSchemaRepository + Send + Sync>,
        credential_repository: Arc<dyn CredentialRepository + Send + Sync>,
        proof_repository: Arc<dyn ProofRepository + Send + Sync>,
        did_repository: Arc<dyn DidRepository + Send + Sync>,
        interaction_repository: Arc<dyn InteractionRepository + Send + Sync>,
        formatter_provider: Arc<dyn CredentialFormatterProvider + Send + Sync>,
        protocol_provider: Arc<dyn TransportProtocolProvider + Send + Sync>,
    ) -> Self {
        Self {
            credential_schema_repository,
            credential_repository,
            proof_repository,
            did_repository,
            interaction_repository,
            formatter_provider,
            protocol_provider,
        }
    }
}

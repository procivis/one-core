use std::sync::Arc;

use crate::config::core_config;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::transport_protocol::provider::TransportProtocolProvider;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::{
    did_repository::DidRepository, proof_repository::ProofRepository,
    proof_schema_repository::ProofSchemaRepository,
};

pub mod dto;
mod mapper;
pub mod service;

#[derive(Clone)]
pub struct ProofService {
    proof_repository: Arc<dyn ProofRepository>,
    proof_schema_repository: Arc<dyn ProofSchemaRepository>,
    did_repository: Arc<dyn DidRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    protocol_provider: Arc<dyn TransportProtocolProvider>,
    config: Arc<core_config::CoreConfig>,
}

impl ProofService {
    pub(crate) fn new(
        proof_repository: Arc<dyn ProofRepository>,
        proof_schema_repository: Arc<dyn ProofSchemaRepository>,
        did_repository: Arc<dyn DidRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
        protocol_provider: Arc<dyn TransportProtocolProvider>,
        config: Arc<core_config::CoreConfig>,
    ) -> Self {
        Self {
            proof_repository,
            proof_schema_repository,
            did_repository,
            history_repository,
            credential_formatter_provider,
            protocol_provider,
            config,
        }
    }
}

#[cfg(test)]
mod test;
mod validator;

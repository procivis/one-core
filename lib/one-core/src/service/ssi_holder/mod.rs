use crate::{
    config::data_structure::CoreConfig,
    crypto::Crypto,
    provider::credential_formatter::provider::CredentialFormatterProvider,
    provider::{
        key_storage::provider::KeyProvider, transport_protocol::provider::TransportProtocolProvider,
    },
    repository::{
        credential_repository::CredentialRepository, did_repository::DidRepository,
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
    credential_repository: Arc<dyn CredentialRepository + Send + Sync>,
    proof_repository: Arc<dyn ProofRepository + Send + Sync>,
    did_repository: Arc<dyn DidRepository + Send + Sync>,
    formatter_provider: Arc<dyn CredentialFormatterProvider + Send + Sync>,
    protocol_provider: Arc<dyn TransportProtocolProvider + Send + Sync>,
    key_provider: Arc<dyn KeyProvider + Send + Sync>,
    crypto: Arc<Crypto>,
    config: Arc<CoreConfig>,
}

#[allow(clippy::too_many_arguments)]
impl SSIHolderService {
    pub(crate) fn new(
        credential_repository: Arc<dyn CredentialRepository + Send + Sync>,
        proof_repository: Arc<dyn ProofRepository + Send + Sync>,
        did_repository: Arc<dyn DidRepository + Send + Sync>,
        formatter_provider: Arc<dyn CredentialFormatterProvider + Send + Sync>,
        protocol_provider: Arc<dyn TransportProtocolProvider + Send + Sync>,
        key_provider: Arc<dyn KeyProvider + Send + Sync>,
        crypto: Arc<Crypto>,
        config: Arc<CoreConfig>,
    ) -> Self {
        Self {
            credential_repository,
            proof_repository,
            did_repository,
            formatter_provider,
            protocol_provider,
            key_provider,
            crypto,
            config,
        }
    }
}

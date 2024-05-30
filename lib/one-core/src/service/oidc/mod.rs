use std::sync::Arc;

use crate::config::core_config;
use crate::crypto::CryptoProvider;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::transport_protocol::provider::TransportProtocolProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::proof_repository::ProofRepository;

pub mod dto;
pub mod mapper;
pub mod model;
pub mod service;
pub mod validator;

#[derive(Clone)]
pub struct OIDCService {
    pub(crate) core_base_url: Option<String>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    credential_repository: Arc<dyn CredentialRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    key_repository: Arc<dyn KeyRepository>,
    key_provider: Arc<dyn KeyProvider>,
    interaction_repository: Arc<dyn InteractionRepository>,
    config: Arc<core_config::CoreConfig>,
    protocol_provider: Arc<dyn TransportProtocolProvider>,
    did_repository: Arc<dyn DidRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    crypto: Arc<dyn CryptoProvider>,
}

#[allow(clippy::too_many_arguments)]
impl OIDCService {
    pub(crate) fn new(
        core_base_url: Option<String>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        credential_repository: Arc<dyn CredentialRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        proof_repository: Arc<dyn ProofRepository>,
        key_repository: Arc<dyn KeyRepository>,
        key_provider: Arc<dyn KeyProvider>,
        interaction_repository: Arc<dyn InteractionRepository>,
        config: Arc<core_config::CoreConfig>,
        protocol_provider: Arc<dyn TransportProtocolProvider>,
        did_repository: Arc<dyn DidRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        crypto: Arc<dyn CryptoProvider>,
    ) -> Self {
        Self {
            core_base_url,
            credential_schema_repository,
            credential_repository,
            proof_repository,
            history_repository,
            key_repository,
            key_provider,
            interaction_repository,
            config,
            protocol_provider,
            did_repository,
            formatter_provider,
            did_method_provider,
            key_algorithm_provider,
            revocation_method_provider,
            crypto,
        }
    }
}

#[cfg(test)]
mod test;

use std::sync::Arc;

use crate::config::core_config;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::transport_protocol::provider::TransportProtocolProvider;
use crate::repository::claim_repository::ClaimRepository;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;

pub mod dto;
pub mod mapper;
pub mod service;
pub mod validator;

mod model;

#[derive(Clone)]
pub struct OIDCService {
    pub(crate) core_base_url: Option<String>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    credential_repository: Arc<dyn CredentialRepository>,
    proof_repository: Arc<dyn ProofRepository + Send + Sync>,
    interaction_repository: Arc<dyn InteractionRepository>,
    config: Arc<core_config::CoreConfig>,
    claim_repository: Arc<dyn ClaimRepository + Send + Sync>,
    protocol_provider: Arc<dyn TransportProtocolProvider + Send + Sync>,
    did_repository: Arc<dyn DidRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider + Send + Sync>,
    did_method_provider: Arc<dyn DidMethodProvider + Send + Sync>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider + Send + Sync>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider + Send + Sync>,
}

#[allow(clippy::too_many_arguments)]
impl OIDCService {
    pub(crate) fn new(
        core_base_url: Option<String>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        credential_repository: Arc<dyn CredentialRepository>,
        proof_repository: Arc<dyn ProofRepository + Send + Sync>,
        interaction_repository: Arc<dyn InteractionRepository>,
        claim_repository: Arc<dyn ClaimRepository + Send + Sync>,
        config: Arc<core_config::CoreConfig>,
        protocol_provider: Arc<dyn TransportProtocolProvider + Send + Sync>,
        did_repository: Arc<dyn DidRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider + Send + Sync>,
        did_method_provider: Arc<dyn DidMethodProvider + Send + Sync>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider + Send + Sync>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider + Send + Sync>,
    ) -> Self {
        Self {
            core_base_url,
            credential_schema_repository,
            credential_repository,
            proof_repository,
            interaction_repository,
            claim_repository,
            config,
            protocol_provider,
            did_repository,
            formatter_provider,
            did_method_provider,
            key_algorithm_provider,
            revocation_method_provider,
        }
    }
}

#[cfg(test)]
mod test;

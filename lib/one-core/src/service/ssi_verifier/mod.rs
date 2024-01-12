use crate::{
    config::core_config,
    provider::{
        credential_formatter::provider::CredentialFormatterProvider,
        did_method::provider::DidMethodProvider, key_algorithm::provider::KeyAlgorithmProvider,
        revocation::provider::RevocationMethodProvider,
    },
    repository::{
        claim_repository::ClaimRepository, claim_schema_repository::ClaimSchemaRepository,
        did_repository::DidRepository, proof_repository::ProofRepository,
    },
};
use std::sync::Arc;

pub mod dto;
pub mod service;

mod mapper;
mod validator;

#[cfg(test)]
mod test;

#[allow(unused)]
#[derive(Clone)]
pub struct SSIVerifierService {
    claim_schema_repository: Arc<dyn ClaimSchemaRepository>,
    claim_repository: Arc<dyn ClaimRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    did_repository: Arc<dyn DidRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    config: Arc<core_config::CoreConfig>,
}

#[allow(clippy::too_many_arguments)]
impl SSIVerifierService {
    pub(crate) fn new(
        claim_schema_repository: Arc<dyn ClaimSchemaRepository>,
        claim_repository: Arc<dyn ClaimRepository>,
        proof_repository: Arc<dyn ProofRepository>,
        did_repository: Arc<dyn DidRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        config: Arc<core_config::CoreConfig>,
    ) -> Self {
        Self {
            claim_schema_repository,
            claim_repository,
            proof_repository,
            did_repository,
            formatter_provider,
            did_method_provider,
            revocation_method_provider,
            key_algorithm_provider,
            config,
        }
    }
}

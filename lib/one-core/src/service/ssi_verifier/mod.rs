use crate::{
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
    claim_schema_repository: Arc<dyn ClaimSchemaRepository + Send + Sync>,
    claim_repository: Arc<dyn ClaimRepository + Send + Sync>,
    proof_repository: Arc<dyn ProofRepository + Send + Sync>,
    did_repository: Arc<dyn DidRepository + Send + Sync>,
    formatter_provider: Arc<dyn CredentialFormatterProvider + Send + Sync>,
    did_method_provider: Arc<dyn DidMethodProvider + Send + Sync>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider + Send + Sync>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider + Send + Sync>,
}

#[allow(clippy::too_many_arguments)]
impl SSIVerifierService {
    pub(crate) fn new(
        claim_schema_repository: Arc<dyn ClaimSchemaRepository + Send + Sync>,
        claim_repository: Arc<dyn ClaimRepository + Send + Sync>,
        proof_repository: Arc<dyn ProofRepository + Send + Sync>,
        did_repository: Arc<dyn DidRepository + Send + Sync>,
        formatter_provider: Arc<dyn CredentialFormatterProvider + Send + Sync>,
        did_method_provider: Arc<dyn DidMethodProvider + Send + Sync>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider + Send + Sync>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider + Send + Sync>,
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
        }
    }
}

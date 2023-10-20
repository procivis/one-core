use crate::{
    config::data_structure::CoreConfig,
    provider::credential_formatter::provider::CredentialFormatterProvider,
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

#[allow(unused)]
#[derive(Clone)]
pub struct SSIVerifierService {
    claim_schema_repository: Arc<dyn ClaimSchemaRepository + Send + Sync>,
    claim_repository: Arc<dyn ClaimRepository + Send + Sync>,
    proof_repository: Arc<dyn ProofRepository + Send + Sync>,
    did_repository: Arc<dyn DidRepository + Send + Sync>,
    formatter_provider: Arc<dyn CredentialFormatterProvider + Send + Sync>,
    config: Arc<CoreConfig>,
}

impl SSIVerifierService {
    pub(crate) fn new(
        claim_schema_repository: Arc<dyn ClaimSchemaRepository + Send + Sync>,
        claim_repository: Arc<dyn ClaimRepository + Send + Sync>,
        proof_repository: Arc<dyn ProofRepository + Send + Sync>,
        did_repository: Arc<dyn DidRepository + Send + Sync>,
        formatter_provider: Arc<dyn CredentialFormatterProvider + Send + Sync>,
        config: Arc<CoreConfig>,
    ) -> Self {
        Self {
            claim_schema_repository,
            claim_repository,
            proof_repository,
            did_repository,
            formatter_provider,
            config,
        }
    }
}

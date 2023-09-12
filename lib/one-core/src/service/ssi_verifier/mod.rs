use crate::{
    credential_formatter::provider::CredentialFormatterProvider,
    repository::{
        claim_schema_repository::ClaimSchemaRepository, did_repository::DidRepository,
        proof_repository::ProofRepository,
    },
};
use std::sync::Arc;

pub mod dto;
pub mod service;

mod mapper;
mod validator;

#[derive(Clone)]
pub struct SSIVerifierService {
    claim_schema_repository: Arc<dyn ClaimSchemaRepository + Send + Sync>,
    proof_repository: Arc<dyn ProofRepository + Send + Sync>,
    did_repository: Arc<dyn DidRepository + Send + Sync>,
    formatter_provider: Arc<dyn CredentialFormatterProvider + Send + Sync>,
}

impl SSIVerifierService {
    pub(crate) fn new(
        claim_schema_repository: Arc<dyn ClaimSchemaRepository + Send + Sync>,
        proof_repository: Arc<dyn ProofRepository + Send + Sync>,
        did_repository: Arc<dyn DidRepository + Send + Sync>,
        formatter_provider: Arc<dyn CredentialFormatterProvider + Send + Sync>,
    ) -> Self {
        Self {
            claim_schema_repository,
            proof_repository,
            did_repository,
            formatter_provider,
        }
    }
}

use crate::repository::{
    claim_schema_repository::ClaimSchemaRepository, did_repository::DidRepository,
    proof_repository::ProofRepository, proof_schema_repository::ProofSchemaRepository,
};
use std::sync::Arc;

pub mod dto;
pub mod service;

mod mapper;

#[derive(Clone)]
pub struct ProofService {
    claim_schema_repository: Arc<dyn ClaimSchemaRepository + Send + Sync>,
    proof_repository: Arc<dyn ProofRepository + Send + Sync>,
    proof_schema_repository: Arc<dyn ProofSchemaRepository + Send + Sync>,
    did_repository: Arc<dyn DidRepository + Send + Sync>,
}

impl ProofService {
    pub fn new(
        claim_schema_repository: Arc<dyn ClaimSchemaRepository + Send + Sync>,
        proof_repository: Arc<dyn ProofRepository + Send + Sync>,
        proof_schema_repository: Arc<dyn ProofSchemaRepository + Send + Sync>,
        did_repository: Arc<dyn DidRepository + Send + Sync>,
    ) -> Self {
        Self {
            claim_schema_repository,
            proof_repository,
            proof_schema_repository,
            did_repository,
        }
    }
}

#[cfg(test)]
mod test;

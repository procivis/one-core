use crate::repository::{
    did_repository::DidRepository, proof_repository::ProofRepository,
    proof_schema_repository::ProofSchemaRepository,
};
use std::sync::Arc;

pub mod dto;
pub mod service;

mod mapper;

#[derive(Clone)]
pub struct ProofService {
    proof_repository: Arc<dyn ProofRepository + Send + Sync>,
    proof_schema_repository: Arc<dyn ProofSchemaRepository + Send + Sync>,
    did_repository: Arc<dyn DidRepository + Send + Sync>,
}

impl ProofService {
    pub fn new(
        proof_repository: Arc<dyn ProofRepository + Send + Sync>,
        proof_schema_repository: Arc<dyn ProofSchemaRepository + Send + Sync>,
        did_repository: Arc<dyn DidRepository + Send + Sync>,
    ) -> Self {
        Self {
            proof_repository,
            proof_schema_repository,
            did_repository,
        }
    }
}

#[cfg(test)]
mod test;

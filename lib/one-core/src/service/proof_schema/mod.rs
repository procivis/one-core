use crate::repository::{
    claim_schema_repository::ClaimSchemaRepository,
    organisation_repository::OrganisationRepository,
    proof_schema_repository::ProofSchemaRepository,
};
use std::sync::Arc;

pub mod dto;
pub mod service;

mod mapper;
mod validator;

#[derive(Clone)]
pub struct ProofSchemaService {
    proof_schema_repository: Arc<dyn ProofSchemaRepository + Send + Sync>,
    claim_schema_repository: Arc<dyn ClaimSchemaRepository + Send + Sync>,
    organisation_repository: Arc<dyn OrganisationRepository + Send + Sync>,
}

impl ProofSchemaService {
    pub fn new(
        proof_schema_repository: Arc<dyn ProofSchemaRepository + Send + Sync>,
        claim_schema_repository: Arc<dyn ClaimSchemaRepository + Send + Sync>,
        organisation_repository: Arc<dyn OrganisationRepository + Send + Sync>,
    ) -> Self {
        Self {
            proof_schema_repository,
            claim_schema_repository,
            organisation_repository,
        }
    }
}

#[cfg(test)]
mod test;

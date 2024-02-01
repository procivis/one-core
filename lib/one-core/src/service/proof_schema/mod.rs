use crate::repository::{
    claim_schema_repository::ClaimSchemaRepository, history_repository::HistoryRepository,
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
    proof_schema_repository: Arc<dyn ProofSchemaRepository>,
    claim_schema_repository: Arc<dyn ClaimSchemaRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    history_repository: Arc<dyn HistoryRepository>,
}

impl ProofSchemaService {
    pub fn new(
        proof_schema_repository: Arc<dyn ProofSchemaRepository>,
        claim_schema_repository: Arc<dyn ClaimSchemaRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        history_repository: Arc<dyn HistoryRepository>,
    ) -> Self {
        Self {
            proof_schema_repository,
            claim_schema_repository,
            organisation_repository,
            history_repository,
        }
    }
}

#[cfg(test)]
mod test;

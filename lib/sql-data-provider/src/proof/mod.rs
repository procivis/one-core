use one_core::repository::{
    claim_repository::ClaimRepository, did_repository::DidRepository,
    interaction_repository::InteractionRepository, proof_schema_repository::ProofSchemaRepository,
};
use sea_orm::DatabaseConnection;
use std::sync::Arc;

mod mapper;
mod model;
pub mod repository;

pub(crate) struct ProofProvider {
    pub db: DatabaseConnection,
    pub proof_schema_repository: Arc<dyn ProofSchemaRepository + Send + Sync>,
    pub claim_repository: Arc<dyn ClaimRepository + Send + Sync>,
    pub did_repository: Arc<dyn DidRepository + Send + Sync>,
    pub interaction_repository: Arc<dyn InteractionRepository + Send + Sync>,
}

#[cfg(test)]
mod test;

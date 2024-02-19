use one_core::repository::{
    claim_repository::ClaimRepository, credential_repository::CredentialRepository,
    did_repository::DidRepository, interaction_repository::InteractionRepository,
    key_repository::KeyRepository, proof_schema_repository::ProofSchemaRepository,
};
use sea_orm::DatabaseConnection;
use std::sync::Arc;

mod mapper;
mod model;
pub mod repository;

pub(crate) struct ProofProvider {
    pub db: DatabaseConnection,
    pub proof_schema_repository: Arc<dyn ProofSchemaRepository>,
    pub claim_repository: Arc<dyn ClaimRepository>,
    pub did_repository: Arc<dyn DidRepository>,
    pub interaction_repository: Arc<dyn InteractionRepository>,
    pub credential_repository: Arc<dyn CredentialRepository>,
    pub key_repository: Arc<dyn KeyRepository>,
}

#[cfg(test)]
mod test;

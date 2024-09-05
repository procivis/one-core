use std::sync::Arc;

use one_core::repository::claim_repository::ClaimRepository;
use one_core::repository::credential_repository::CredentialRepository;
use one_core::repository::did_repository::DidRepository;
use one_core::repository::interaction_repository::InteractionRepository;
use one_core::repository::key_repository::KeyRepository;
use one_core::repository::proof_schema_repository::ProofSchemaRepository;
use sea_orm::DatabaseConnection;

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

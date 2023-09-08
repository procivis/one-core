use sea_orm::DatabaseConnection;
use std::sync::Arc;

use one_core::repository::{
    claim_repository::ClaimRepository, credential_schema_repository::CredentialSchemaRepository,
    did_repository::DidRepository,
};

pub mod mapper;
pub mod repository;

pub(crate) struct CredentialProvider {
    pub db: DatabaseConnection,
    pub credential_schema_repository: Arc<dyn CredentialSchemaRepository + Send + Sync>,
    pub claim_repository: Arc<dyn ClaimRepository + Send + Sync>,
    pub did_repository: Arc<dyn DidRepository + Send + Sync>,
}

#[cfg(test)]
mod test;

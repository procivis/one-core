use sea_orm::DatabaseConnection;
use std::sync::Arc;

use one_core::repository::{
    claim_repository::ClaimRepository, credential_schema_repository::CredentialSchemaRepository,
    did_repository::DidRepository, interaction_repository::InteractionRepository,
    key_repository::KeyRepository, revocation_list_repository::RevocationListRepository,
};

pub mod mapper;
pub mod repository;

pub(crate) struct CredentialProvider {
    pub db: DatabaseConnection,
    pub credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    pub claim_repository: Arc<dyn ClaimRepository>,
    pub did_repository: Arc<dyn DidRepository>,
    pub interaction_repository: Arc<dyn InteractionRepository>,
    pub revocation_list_repository: Arc<dyn RevocationListRepository>,
    pub key_repository: Arc<dyn KeyRepository>,
}

#[cfg(test)]
mod test;

use std::sync::Arc;

use one_core::repository::claim_repository::ClaimRepository;
use one_core::repository::credential_schema_repository::CredentialSchemaRepository;
use one_core::repository::did_repository::DidRepository;
use one_core::repository::interaction_repository::InteractionRepository;
use one_core::repository::key_repository::KeyRepository;
use one_core::repository::revocation_list_repository::RevocationListRepository;
use sea_orm::DatabaseConnection;

mod entity_model;
pub mod history;
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

use one_core::repository::claim_schema_repository::ClaimSchemaRepository;
use sea_orm::DatabaseConnection;
use std::sync::Arc;

use one_core::repository::organisation_repository::OrganisationRepository;

pub mod mapper;
pub mod repository;

pub(crate) struct CredentialSchemaProvider {
    pub db: DatabaseConnection,
    pub claim_schema_repository: Arc<dyn ClaimSchemaRepository + Send + Sync>,
    pub organisation_repository: Arc<dyn OrganisationRepository + Send + Sync>,
}

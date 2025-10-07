use std::sync::Arc;

use one_core::repository::claim_schema_repository::ClaimSchemaRepository;
use one_core::repository::credential_schema_repository::CredentialSchemaRepository;
use one_core::repository::organisation_repository::OrganisationRepository;
use sea_orm::DatabaseConnection;

mod mapper;
pub mod repository;

pub(crate) struct ProofSchemaProvider {
    pub db: DatabaseConnection,
    pub claim_schema_repository: Arc<dyn ClaimSchemaRepository>,
    pub organisation_repository: Arc<dyn OrganisationRepository>,
    pub credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
}

#[cfg(test)]
mod test;

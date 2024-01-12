use one_core::repository::{
    claim_schema_repository::ClaimSchemaRepository,
    credential_schema_repository::CredentialSchemaRepository,
    organisation_repository::OrganisationRepository,
};
use sea_orm::DatabaseConnection;
use std::sync::Arc;

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

use std::sync::Arc;

use sea_orm::DatabaseConnection;

use one_core::repository::{
    credential_repository::CredentialRepository, did_repository::DidRepository,
    organisation_repository::OrganisationRepository,
};

mod mapper;
mod repository;

pub(crate) struct KeyProvider {
    pub db: DatabaseConnection,
    pub credential_repository: Arc<dyn CredentialRepository + Send + Sync>,
    pub did_repository: Arc<dyn DidRepository + Send + Sync>,
    pub organisation_repository: Arc<dyn OrganisationRepository + Send + Sync>,
}

#[cfg(test)]
mod test;

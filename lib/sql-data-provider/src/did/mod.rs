use one_core::repository::{
    key_repository::KeyRepository, organisation_repository::OrganisationRepository,
};
use sea_orm::DatabaseConnection;
use std::sync::Arc;

pub mod mapper;
pub mod repository;

pub(crate) struct DidProvider {
    pub db: DatabaseConnection,
    pub organisation_repository: Arc<dyn OrganisationRepository>,
    pub key_repository: Arc<dyn KeyRepository>,
}

#[cfg(test)]
mod test;

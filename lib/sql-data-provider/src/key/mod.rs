use std::sync::Arc;

use sea_orm::DatabaseConnection;

use one_core::repository::organisation_repository::OrganisationRepository;

mod mapper;
mod repository;

pub(crate) struct KeyProvider {
    pub db: DatabaseConnection,
    pub organisation_repository: Arc<dyn OrganisationRepository + Send + Sync>,
}

#[cfg(test)]
mod test;

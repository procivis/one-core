use std::sync::Arc;

use one_core::repository::organisation_repository::OrganisationRepository;
use sea_orm::DatabaseConnection;

pub mod history;
mod mapper;
mod repository;

pub(crate) struct KeyProvider {
    pub db: DatabaseConnection,
    pub organisation_repository: Arc<dyn OrganisationRepository>,
}

#[cfg(test)]
mod test;

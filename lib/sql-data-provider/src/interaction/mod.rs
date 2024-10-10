use std::sync::Arc;

use one_core::repository::organisation_repository::OrganisationRepository;
use sea_orm::DatabaseConnection;

pub mod mapper;
pub mod repository;

pub(crate) struct InteractionProvider {
    pub db: DatabaseConnection,
    pub organisation_repository: Arc<dyn OrganisationRepository>,
}

#[cfg(test)]
mod test;

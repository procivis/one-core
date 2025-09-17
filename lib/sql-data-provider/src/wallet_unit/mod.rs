use std::sync::Arc;

use one_core::repository::organisation_repository::OrganisationRepository;
use sea_orm::DatabaseConnection;

pub mod mapper;
pub mod repository;

#[cfg(test)]
mod test;

pub(crate) struct WalletUnitProvider {
    pub db: DatabaseConnection,
    pub organisation_repository: Arc<dyn OrganisationRepository>,
}

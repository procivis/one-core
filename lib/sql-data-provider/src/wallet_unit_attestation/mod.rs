use std::sync::Arc;

use one_core::repository::key_repository::KeyRepository;
use one_core::repository::organisation_repository::OrganisationRepository;
use sea_orm::DatabaseConnection;

pub mod repository;

#[cfg(test)]
mod test;

pub(crate) struct WalletUnitAttestationProvider {
    pub db: DatabaseConnection,
    pub key_repository: Arc<dyn KeyRepository>,
    pub organisation_repository: Arc<dyn OrganisationRepository>,
}

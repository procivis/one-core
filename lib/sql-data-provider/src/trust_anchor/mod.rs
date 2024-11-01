use std::sync::Arc;

use one_core::repository::organisation_repository::OrganisationRepository;
use sea_orm::DatabaseConnection;

pub mod entities;
pub mod history;
pub mod mapper;
pub mod repository;

pub(crate) struct TrustAnchorProvider {
    pub organisation_repository: Arc<dyn OrganisationRepository>,
    pub db: DatabaseConnection,
}

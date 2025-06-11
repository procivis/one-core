use std::sync::Arc;

use one_core::repository::organisation_repository::OrganisationRepository;
use one_core::repository::trust_anchor_repository::TrustAnchorRepository;
use sea_orm::DatabaseConnection;

pub mod history;
pub mod mapper;
pub mod model;
pub mod repository;

pub(crate) struct TrustEntityProvider {
    pub trust_anchor_repository: Arc<dyn TrustAnchorRepository>,
    pub organisation_repository: Arc<dyn OrganisationRepository>,
    pub db: DatabaseConnection,
}

use std::sync::Arc;

use one_core::repository::trust_anchor_repository::TrustAnchorRepository;
use sea_orm::DatabaseConnection;

pub mod mapper;
pub mod model;
pub mod repository;

pub(crate) struct TrustEntityProvider {
    pub trust_anchor_repository: Arc<dyn TrustAnchorRepository>,
    pub db: DatabaseConnection,
}

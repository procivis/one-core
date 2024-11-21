use std::sync::Arc;

use one_core::repository::did_repository::DidRepository;
use one_core::repository::trust_anchor_repository::TrustAnchorRepository;
use sea_orm::DatabaseConnection;

pub mod history;
pub mod mapper;
pub mod model;
pub mod repository;

pub(crate) struct TrustEntityProvider {
    pub trust_anchor_repository: Arc<dyn TrustAnchorRepository>,
    pub did_repository: Arc<dyn DidRepository>,
    pub db: DatabaseConnection,
}

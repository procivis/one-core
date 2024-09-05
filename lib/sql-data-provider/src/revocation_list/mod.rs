use std::sync::Arc;

use one_core::repository::did_repository::DidRepository;
use sea_orm::DatabaseConnection;

pub mod repository;

pub(crate) struct RevocationListProvider {
    pub db: DatabaseConnection,
    pub did_repository: Arc<dyn DidRepository>,
}

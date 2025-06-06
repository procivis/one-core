use std::sync::Arc;

use one_core::repository::identifier_repository::IdentifierRepository;
use sea_orm::DatabaseConnection;

pub mod repository;

pub(crate) struct RevocationListProvider {
    pub db: DatabaseConnection,
    pub identifier_repository: Arc<dyn IdentifierRepository>,
}

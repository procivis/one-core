use sea_orm::DatabaseConnection;

pub mod repository;

pub(crate) struct TrustProvider {
    pub _db: DatabaseConnection,
}

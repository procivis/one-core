use sea_orm::DatabaseConnection;

pub mod repository;

pub(crate) struct TrustEntityProvider {
    pub db: DatabaseConnection,
}

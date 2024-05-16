use sea_orm::DatabaseConnection;

pub mod repository;

pub(crate) struct TrustAnchorProvider {
    pub db: DatabaseConnection,
}

use sea_orm::DatabaseConnection;

pub mod entities;
pub mod mapper;
pub mod repository;

pub(crate) struct TrustAnchorProvider {
    pub db: DatabaseConnection,
}

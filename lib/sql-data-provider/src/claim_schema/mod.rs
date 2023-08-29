use sea_orm::DatabaseConnection;

pub mod mapper;
pub mod repository;

pub(crate) struct ClaimSchemaProvider {
    pub db: DatabaseConnection,
}

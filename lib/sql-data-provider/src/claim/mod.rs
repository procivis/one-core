use one_core::repository::claim_schema_repository::ClaimSchemaRepository;
use sea_orm::DatabaseConnection;
use std::sync::Arc;

pub mod mapper;
pub mod repository;

pub(crate) struct ClaimProvider {
    pub db: DatabaseConnection,
    pub claim_schema_repository: Arc<dyn ClaimSchemaRepository + Send + Sync>,
}

#[cfg(test)]
mod test;

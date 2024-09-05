use std::sync::Arc;

use one_core::repository::claim_schema_repository::ClaimSchemaRepository;
use sea_orm::DatabaseConnection;

pub mod mapper;
pub mod repository;

pub(crate) struct ClaimProvider {
    pub db: DatabaseConnection,
    pub claim_schema_repository: Arc<dyn ClaimSchemaRepository>,
}

#[cfg(test)]
mod test;

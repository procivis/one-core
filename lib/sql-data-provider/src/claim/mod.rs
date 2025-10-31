use std::sync::Arc;

use one_core::repository::claim_schema_repository::ClaimSchemaRepository;

use crate::transaction_context::TransactionManagerImpl;

pub mod mapper;
pub mod repository;

pub(crate) struct ClaimProvider {
    pub db: TransactionManagerImpl,
    pub claim_schema_repository: Arc<dyn ClaimSchemaRepository>,
}

#[cfg(test)]
mod test;

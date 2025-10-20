use std::sync::Arc;

use one_core::repository::claim_schema_repository::ClaimSchemaRepository;

use crate::transaction_context::TransactionProvider;

pub mod mapper;
pub mod repository;

pub(crate) struct ClaimProvider {
    pub db: Arc<dyn TransactionProvider>,
    pub claim_schema_repository: Arc<dyn ClaimSchemaRepository>,
}

#[cfg(test)]
mod test;

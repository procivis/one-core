use std::sync::Arc;

use crate::transaction_context::TransactionProvider;

pub mod mapper;
pub mod repository;

pub(crate) struct ClaimSchemaProvider {
    pub db: Arc<dyn TransactionProvider>,
}

#[cfg(test)]
mod test;

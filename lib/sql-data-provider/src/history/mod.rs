use std::sync::Arc;

use crate::transaction_context::TransactionProvider;

pub mod mapper;
pub mod queries;
pub mod repository;

pub(crate) struct HistoryProvider {
    pub db: Arc<dyn TransactionProvider>,
}

#[cfg(test)]
mod test;

use std::sync::Arc;

use crate::transaction_context::TransactionProvider;

pub mod mapper;
pub mod repository;
pub(crate) struct BlobProvider {
    db: Arc<dyn TransactionProvider>,
}

impl BlobProvider {
    pub fn new(db: Arc<dyn TransactionProvider>) -> Self {
        Self { db }
    }
}

#[cfg(test)]
mod test;

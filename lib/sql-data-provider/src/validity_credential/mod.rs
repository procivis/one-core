use std::sync::Arc;

use crate::transaction_context::TransactionProvider;

mod mapper;
mod repository;

#[cfg(test)]
mod test;

pub struct ValidityCredentialProvider {
    db_conn: Arc<dyn TransactionProvider>,
}

impl ValidityCredentialProvider {
    pub fn new(db_conn: Arc<dyn TransactionProvider>) -> Self {
        Self { db_conn }
    }
}

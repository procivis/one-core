use std::sync::Arc;

use crate::transaction_context::TransactionProvider;

pub mod entities;
pub mod mapper;
pub mod repository;

pub(crate) struct TrustAnchorProvider {
    pub db: Arc<dyn TransactionProvider>,
}

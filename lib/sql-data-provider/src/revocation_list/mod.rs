use std::sync::Arc;

use one_core::repository::identifier_repository::IdentifierRepository;

use crate::transaction_context::TransactionProvider;

pub mod repository;

pub(crate) struct RevocationListProvider {
    pub db: Arc<dyn TransactionProvider>,
    pub identifier_repository: Arc<dyn IdentifierRepository>,
}

use std::sync::Arc;

use one_core::repository::key_repository::KeyRepository;

use crate::transaction_context::TransactionManagerImpl;
mod mapper;
pub mod repository;

pub(crate) struct WalletAttestationProvider {
    pub db: TransactionManagerImpl,
    pub key_repository: Arc<dyn KeyRepository>,
}

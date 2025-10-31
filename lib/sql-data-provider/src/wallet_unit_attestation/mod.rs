use std::sync::Arc;

use one_core::repository::key_repository::KeyRepository;

use crate::transaction_context::TransactionManagerImpl;
mod mapper;
pub mod repository;
#[cfg(test)]
mod test;
pub(crate) struct WalletUnitAttestationProvider {
    pub db: TransactionManagerImpl,
    pub key_repository: Arc<dyn KeyRepository>,
}

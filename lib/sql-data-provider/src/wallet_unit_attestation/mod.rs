use std::sync::Arc;

use one_core::repository::key_repository::KeyRepository;

use crate::transaction_context::TransactionProvider;
mod mapper;
pub mod repository;
#[cfg(test)]
mod test;
pub(crate) struct WalletUnitAttestationProvider {
    pub db: Arc<dyn TransactionProvider>,
    pub key_repository: Arc<dyn KeyRepository>,
}

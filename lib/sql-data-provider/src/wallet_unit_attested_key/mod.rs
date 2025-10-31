mod mapper;
mod repository;

use std::sync::Arc;

use one_core::repository::revocation_list_repository::RevocationListRepository;

use crate::transaction_context::TransactionManagerImpl;

pub(crate) struct WalletUnitAttestedKeyProvider {
    pub db: TransactionManagerImpl,
    pub revocation_list_repository: Arc<dyn RevocationListRepository>,
}

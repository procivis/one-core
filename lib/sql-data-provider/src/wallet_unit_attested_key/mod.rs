mod mapper;
mod repository;

use std::sync::Arc;

use one_core::repository::revocation_list_repository::RevocationListRepository;

use crate::transaction_context::TransactionProvider;

pub(crate) struct WalletUnitAttestedKeyProvider {
    pub db: Arc<dyn TransactionProvider>,
    pub revocation_list_repository: Arc<dyn RevocationListRepository>,
}

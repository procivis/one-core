use std::sync::Arc;

use one_core::proto::transaction_manager::TransactionManager;
use one_core::repository::organisation_repository::OrganisationRepository;
use one_core::repository::wallet_unit_attested_key_repository::WalletUnitAttestedKeyRepository;

use crate::transaction_context::TransactionProvider;

pub mod mapper;
pub mod repository;

#[cfg(test)]
mod test;

pub(crate) struct WalletUnitProvider {
    pub db: Arc<dyn TransactionProvider>,
    pub tx_manager: Arc<dyn TransactionManager>,
    pub organisation_repository: Arc<dyn OrganisationRepository>,
    pub wallet_unit_attested_key_repository: Arc<dyn WalletUnitAttestedKeyRepository>,
}

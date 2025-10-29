mod mapper;
mod repository;

use std::sync::Arc;

use one_core::proto::transaction_manager::TransactionManager;
use one_core::repository::key_repository::KeyRepository;
use one_core::repository::organisation_repository::OrganisationRepository;
use one_core::repository::wallet_unit_attestation_repository::WalletUnitAttestationRepository;

use crate::transaction_context::TransactionProvider;

pub(crate) struct HolderWalletUnitProvider {
    pub db: Arc<dyn TransactionProvider>,
    pub tx_manager: Arc<dyn TransactionManager>,
    pub organisation_repository: Arc<dyn OrganisationRepository>,
    pub key_repository: Arc<dyn KeyRepository>,
    pub wallet_unit_attestation_repository: Arc<dyn WalletUnitAttestationRepository>,
}

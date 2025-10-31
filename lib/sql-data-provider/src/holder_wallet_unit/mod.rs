mod mapper;
mod repository;
#[cfg(test)]
mod test;

use std::sync::Arc;

use one_core::repository::key_repository::KeyRepository;
use one_core::repository::organisation_repository::OrganisationRepository;
use one_core::repository::wallet_unit_attestation_repository::WalletUnitAttestationRepository;

use crate::transaction_context::TransactionManagerImpl;

pub(crate) struct HolderWalletUnitProvider {
    pub db: TransactionManagerImpl,
    pub organisation_repository: Arc<dyn OrganisationRepository>,
    pub key_repository: Arc<dyn KeyRepository>,
    pub wallet_unit_attestation_repository: Arc<dyn WalletUnitAttestationRepository>,
}

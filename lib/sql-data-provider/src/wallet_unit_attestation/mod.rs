use std::sync::Arc;

use one_core::repository::key_repository::KeyRepository;
use one_core::repository::organisation_repository::OrganisationRepository;

use crate::transaction_context::TransactionProvider;

pub mod repository;

#[cfg(test)]
mod test;

pub(crate) struct WalletUnitAttestationProvider {
    pub db: Arc<dyn TransactionProvider>,
    pub key_repository: Arc<dyn KeyRepository>,
    pub organisation_repository: Arc<dyn OrganisationRepository>,
}

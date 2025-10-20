use std::sync::Arc;

use one_core::repository::organisation_repository::OrganisationRepository;

use crate::transaction_context::TransactionProvider;

pub mod mapper;
pub mod repository;

#[cfg(test)]
mod test;

pub(crate) struct WalletUnitProvider {
    pub db: Arc<dyn TransactionProvider>,
    pub organisation_repository: Arc<dyn OrganisationRepository>,
}

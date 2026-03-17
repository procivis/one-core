use std::sync::Arc;

use one_core::repository::organisation_repository::OrganisationRepository;

use crate::transaction_context::TransactionManagerImpl;

mod mapper;
mod repository;
#[cfg(test)]
mod test;

pub(crate) struct TrustCollectionProvider {
    pub db: TransactionManagerImpl,
    pub organisation_repository: Arc<dyn OrganisationRepository>,
}

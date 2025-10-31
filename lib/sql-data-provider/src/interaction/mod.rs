use std::sync::Arc;

use one_core::repository::organisation_repository::OrganisationRepository;

use crate::transaction_context::TransactionManagerImpl;

pub mod mapper;
pub mod repository;

pub(crate) struct InteractionProvider {
    pub db: TransactionManagerImpl,
    pub organisation_repository: Arc<dyn OrganisationRepository>,
}

#[cfg(test)]
mod test;

use std::sync::Arc;

use one_core::repository::organisation_repository::OrganisationRepository;

use crate::transaction_context::TransactionProvider;

mod mapper;
mod repository;

pub(crate) struct KeyProvider {
    pub db: Arc<dyn TransactionProvider>,
    pub organisation_repository: Arc<dyn OrganisationRepository>,
}

#[cfg(test)]
mod test;

use std::sync::Arc;

use crate::transaction_context::TransactionProvider;

mod mapper;
pub mod repository;

#[cfg(test)]
mod test;

pub(crate) struct OrganisationProvider {
    pub db: Arc<dyn TransactionProvider>,
}

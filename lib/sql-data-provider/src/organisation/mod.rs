use crate::transaction_context::TransactionManagerImpl;

mod mapper;
pub mod repository;

#[cfg(test)]
mod test;

pub(crate) struct OrganisationProvider {
    pub db: TransactionManagerImpl,
}

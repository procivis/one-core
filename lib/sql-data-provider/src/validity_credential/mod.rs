use crate::transaction_context::TransactionManagerImpl;

mod mapper;
mod repository;

pub struct ValidityCredentialProvider {
    pub db: TransactionManagerImpl,
}

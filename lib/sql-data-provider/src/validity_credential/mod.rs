use crate::transaction_context::TransactionManagerImpl;

mod mapper;
mod repository;

#[cfg(test)]
mod test;

pub struct ValidityCredentialProvider {
    pub db: TransactionManagerImpl,
}

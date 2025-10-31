use crate::transaction_context::TransactionManagerImpl;

pub mod mapper;
pub mod repository;
pub(crate) struct BlobProvider {
    pub db: TransactionManagerImpl,
}

#[cfg(test)]
mod test;

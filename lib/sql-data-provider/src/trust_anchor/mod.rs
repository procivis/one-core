use crate::transaction_context::TransactionManagerImpl;

pub mod entities;
pub mod mapper;
pub mod repository;

pub(crate) struct TrustAnchorProvider {
    pub db: TransactionManagerImpl,
}

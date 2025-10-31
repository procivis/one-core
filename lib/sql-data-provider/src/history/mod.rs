use crate::transaction_context::TransactionManagerImpl;

pub mod mapper;
pub mod queries;
pub mod repository;

pub(crate) struct HistoryProvider {
    pub db: TransactionManagerImpl,
}

#[cfg(test)]
mod test;

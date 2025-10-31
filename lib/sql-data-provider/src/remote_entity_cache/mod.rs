use crate::transaction_context::TransactionManagerImpl;

pub mod mapper;
pub mod repository;

pub(crate) struct RemoteEntityCacheProvider {
    pub db: TransactionManagerImpl,
}

#[cfg(test)]
mod test;

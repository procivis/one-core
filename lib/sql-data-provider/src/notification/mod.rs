use crate::transaction_context::TransactionManagerImpl;

mod mapper;
mod repository;

pub(crate) struct NotificationProvider {
    pub db: TransactionManagerImpl,
}

#[cfg(test)]
mod test;

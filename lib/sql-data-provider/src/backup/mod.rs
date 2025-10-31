use crate::transaction_context::TransactionManagerImpl;

mod helpers;
mod mappers;
mod models;
pub mod repository;

pub(crate) struct BackupProvider {
    pub db: TransactionManagerImpl,
    exportable_storages: Vec<String>,
}

#[cfg(test)]
mod test;

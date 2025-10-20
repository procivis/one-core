use std::sync::Arc;

use crate::transaction_context::TransactionProvider;

mod helpers;
mod mappers;
mod models;
pub mod repository;

pub(crate) struct BackupProvider {
    db: Arc<dyn TransactionProvider>,
    exportable_storages: Vec<String>,
}

#[cfg(test)]
mod test;

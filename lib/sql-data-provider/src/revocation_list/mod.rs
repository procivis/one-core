use std::sync::Arc;

use one_core::repository::certificate_repository::CertificateRepository;
use one_core::repository::identifier_repository::IdentifierRepository;

use crate::transaction_context::TransactionManagerImpl;

pub mod repository;

pub(crate) struct RevocationListProvider {
    pub db: TransactionManagerImpl,
    pub identifier_repository: Arc<dyn IdentifierRepository>,
    pub certificate_repository: Arc<dyn CertificateRepository>,
}

#[cfg(test)]
mod test;

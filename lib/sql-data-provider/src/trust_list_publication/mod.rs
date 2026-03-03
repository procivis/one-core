use std::sync::Arc;

use one_core::repository::certificate_repository::CertificateRepository;
use one_core::repository::identifier_repository::IdentifierRepository;
use one_core::repository::key_repository::KeyRepository;
use one_core::repository::organisation_repository::OrganisationRepository;

use crate::transaction_context::TransactionManagerImpl;

mod mapper;
mod repository;

#[cfg(test)]
mod test;

pub(crate) struct TrustListPublicationProvider {
    pub db: TransactionManagerImpl,
    pub organisation_repository: Arc<dyn OrganisationRepository>,
    pub identifier_repository: Arc<dyn IdentifierRepository>,
    pub key_repository: Arc<dyn KeyRepository>,
    pub certificate_repository: Arc<dyn CertificateRepository>,
}

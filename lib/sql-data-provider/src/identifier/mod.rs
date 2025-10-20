use std::sync::Arc;

use one_core::repository::certificate_repository::CertificateRepository;
use one_core::repository::did_repository::DidRepository;
use one_core::repository::key_repository::KeyRepository;
use one_core::repository::organisation_repository::OrganisationRepository;

use crate::transaction_context::TransactionProvider;

pub mod mapper;
pub mod repository;

pub(crate) struct IdentifierProvider {
    pub db: Arc<dyn TransactionProvider>,

    pub organisation_repository: Arc<dyn OrganisationRepository>,
    pub did_repository: Arc<dyn DidRepository>,
    pub key_repository: Arc<dyn KeyRepository>,
    pub certificate_repository: Arc<dyn CertificateRepository>,
}

#[cfg(test)]
mod test;

use std::sync::Arc;

use one_core::repository::certificate_repository::CertificateRepository;
use one_core::repository::did_repository::DidRepository;
use one_core::repository::identifier_trust_information_repository::IdentifierTrustInformationRepository;
use one_core::repository::key_repository::KeyRepository;
use one_core::repository::localized_text_repository::LocalizedTextRepository;
use one_core::repository::organisation_repository::OrganisationRepository;

use crate::transaction_context::TransactionManagerImpl;

pub mod mapper;
pub mod repository;

pub(crate) struct IdentifierProvider {
    pub db: TransactionManagerImpl,

    pub organisation_repository: Arc<dyn OrganisationRepository>,
    pub did_repository: Arc<dyn DidRepository>,
    pub key_repository: Arc<dyn KeyRepository>,
    pub certificate_repository: Arc<dyn CertificateRepository>,
    pub trust_information_repository: Arc<dyn IdentifierTrustInformationRepository>,
    pub localized_text_repository: Arc<dyn LocalizedTextRepository>,
}

#[cfg(test)]
mod test;

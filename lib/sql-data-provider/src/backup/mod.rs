use std::sync::Arc;

use one_core::repository::certificate_repository::CertificateRepository;
use one_core::repository::did_repository::DidRepository;
use one_core::repository::identifier_trust_information_repository::IdentifierTrustInformationRepository;
use one_core::repository::key_repository::KeyRepository;
use one_core::repository::localized_text_repository::LocalizedTextRepository;
use one_core::repository::organisation_repository::OrganisationRepository;

use crate::transaction_context::TransactionManagerImpl;

mod helpers;
mod mappers;
mod models;
pub mod repository;

pub(crate) struct BackupProvider {
    pub db: TransactionManagerImpl,
    exportable_storages: Vec<String>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    did_repository: Arc<dyn DidRepository>,
    key_repository: Arc<dyn KeyRepository>,
    certificate_repository: Arc<dyn CertificateRepository>,
    trust_information_repository: Arc<dyn IdentifierTrustInformationRepository>,
    localized_text_repository: Arc<dyn LocalizedTextRepository>,
}

#[cfg(test)]
mod test;

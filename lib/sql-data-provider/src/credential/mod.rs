use std::sync::Arc;

use one_core::repository::certificate_repository::CertificateRepository;
use one_core::repository::claim_repository::ClaimRepository;
use one_core::repository::credential_repository::CredentialRepository;
use one_core::repository::credential_schema_repository::CredentialSchemaRepository;
use one_core::repository::identifier_repository::IdentifierRepository;
use one_core::repository::interaction_repository::InteractionRepository;
use one_core::repository::key_repository::KeyRepository;
use one_core::repository::organisation_repository::OrganisationRepository;

use crate::transaction_context::TransactionManagerImpl;

mod claim_deduplication;
mod creation;
pub mod mapper;
pub mod repository;
mod update;

#[derive(Clone)]
pub(crate) struct CredentialProvider {
    pub db: TransactionManagerImpl,
    pub credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    pub claim_repository: Arc<dyn ClaimRepository>,
    pub identifier_repository: Arc<dyn IdentifierRepository>,
    pub interaction_repository: Arc<dyn InteractionRepository>,
    pub certificate_repository: Arc<dyn CertificateRepository>,
    pub key_repository: Arc<dyn KeyRepository>,
    pub organisation_repository: Arc<dyn OrganisationRepository>,
}

impl CredentialProvider {
    fn cloned(&self) -> Arc<dyn CredentialRepository> {
        Arc::new(self.clone())
    }
}

#[cfg(test)]
mod test;

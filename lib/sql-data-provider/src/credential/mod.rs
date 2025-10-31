use std::sync::Arc;

use one_core::repository::certificate_repository::CertificateRepository;
use one_core::repository::claim_repository::ClaimRepository;
use one_core::repository::credential_schema_repository::CredentialSchemaRepository;
use one_core::repository::identifier_repository::IdentifierRepository;
use one_core::repository::interaction_repository::InteractionRepository;
use one_core::repository::key_repository::KeyRepository;
use one_core::repository::revocation_list_repository::RevocationListRepository;

use crate::transaction_context::TransactionManagerImpl;

mod entity_model;
pub mod mapper;
pub mod repository;

pub(crate) struct CredentialProvider {
    pub db: TransactionManagerImpl,
    pub credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    pub claim_repository: Arc<dyn ClaimRepository>,
    pub identifier_repository: Arc<dyn IdentifierRepository>,
    pub interaction_repository: Arc<dyn InteractionRepository>,
    pub revocation_list_repository: Arc<dyn RevocationListRepository>,
    pub certificate_repository: Arc<dyn CertificateRepository>,
    pub key_repository: Arc<dyn KeyRepository>,
}

#[cfg(test)]
mod test;

use std::sync::Arc;

use one_core::repository::certificate_repository::CertificateRepository;
use one_core::repository::claim_repository::ClaimRepository;
use one_core::repository::credential_repository::CredentialRepository;
use one_core::repository::did_repository::DidRepository;
use one_core::repository::identifier_repository::IdentifierRepository;
use one_core::repository::identifier_trust_information_repository::IdentifierTrustInformationRepository;
use one_core::repository::interaction_repository::InteractionRepository;
use one_core::repository::key_repository::KeyRepository;
use one_core::repository::localized_text_repository::LocalizedTextRepository;
use one_core::repository::organisation_repository::OrganisationRepository;
use one_core::repository::proof_schema_repository::ProofSchemaRepository;

use crate::transaction_context::TransactionManagerImpl;

mod mapper;
mod model;
pub mod repository;

pub(crate) struct ProofProvider {
    pub db: TransactionManagerImpl,
    pub proof_schema_repository: Arc<dyn ProofSchemaRepository>,
    pub claim_repository: Arc<dyn ClaimRepository>,
    pub identifier_repository: Arc<dyn IdentifierRepository>,
    pub did_repository: Arc<dyn DidRepository>,
    pub certificate_repository: Arc<dyn CertificateRepository>,
    pub interaction_repository: Arc<dyn InteractionRepository>,
    pub credential_repository: Arc<dyn CredentialRepository>,
    pub key_repository: Arc<dyn KeyRepository>,
    pub organisation_repository: Arc<dyn OrganisationRepository>,
    pub trust_information_repository: Arc<dyn IdentifierTrustInformationRepository>,
    pub localized_text_repository: Arc<dyn LocalizedTextRepository>,
}

#[cfg(test)]
mod test;

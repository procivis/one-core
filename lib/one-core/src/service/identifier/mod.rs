use std::sync::Arc;

use crate::config::core_config;
use crate::error::ErrorCode;
use crate::proto::identifier_creator::IdentifierCreator;
use crate::proto::session_provider::SessionProvider;
use crate::proto::transaction_manager::TransactionManager;
use crate::proto::wrp_validator::WRPValidator;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::ecosystem::directory::EcosystemDirectory;
use crate::provider::trust_list_subscriber::provider::TrustListSubscriberProvider;
use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::identifier_trust_information_repository::IdentifierTrustInformationRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::proof_schema_repository::ProofSchemaRepository;
use crate::repository::trust_collection_repository::TrustCollectionRepository;
use crate::repository::trust_list_subscription_repository::TrustListSubscriptionRepository;

pub mod dto;
pub mod error;
pub(crate) mod mapper;
pub mod service;
#[cfg(test)]
mod test;
mod validator;

#[derive(Clone)]
pub struct IdentifierService {
    identifier_repository: Arc<dyn IdentifierRepository>,
    certificate_repository: Arc<dyn CertificateRepository>,
    did_repository: Arc<dyn DidRepository>,
    key_repository: Arc<dyn KeyRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    proof_schema_repository: Arc<dyn ProofSchemaRepository>,
    trust_collection_repository: Arc<dyn TrustCollectionRepository>,
    trust_list_subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
    identifier_trust_information_repository: Arc<dyn IdentifierTrustInformationRepository>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
    config: Arc<core_config::CoreConfig>,
    identifier_creator: Arc<dyn IdentifierCreator>,
    session_provider: Arc<dyn SessionProvider>,
    trust_list_subscriber_provider: Arc<dyn TrustListSubscriberProvider>,
    transaction_manager: Arc<dyn TransactionManager>,
    wrp_validator: Arc<dyn WRPValidator>,
    ecosystem_provider: Arc<dyn EcosystemDirectory>,
}

impl IdentifierService {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        identifier_repository: Arc<dyn IdentifierRepository>,
        certificate_repository: Arc<dyn CertificateRepository>,
        did_repository: Arc<dyn DidRepository>,
        key_repository: Arc<dyn KeyRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        proof_schema_repository: Arc<dyn ProofSchemaRepository>,
        trust_collection_repository: Arc<dyn TrustCollectionRepository>,
        trust_list_subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
        identifier_trust_information_repository: Arc<dyn IdentifierTrustInformationRepository>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        identifier_creator: Arc<dyn IdentifierCreator>,
        config: Arc<core_config::CoreConfig>,
        session_provider: Arc<dyn SessionProvider>,
        trust_list_subscriber_provider: Arc<dyn TrustListSubscriberProvider>,
        transaction_manager: Arc<dyn TransactionManager>,
        wrp_validator: Arc<dyn WRPValidator>,
        ecosystem_provider: Arc<dyn EcosystemDirectory>,
    ) -> Self {
        Self {
            identifier_repository,
            certificate_repository,
            did_repository,
            key_repository,
            organisation_repository,
            credential_schema_repository,
            trust_list_subscription_repository,
            trust_collection_repository,
            blob_storage_provider,
            identifier_creator,
            config,
            session_provider,
            trust_list_subscriber_provider,
            proof_schema_repository,
            identifier_trust_information_repository,
            transaction_manager,
            wrp_validator,
            ecosystem_provider,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum IdentifierError {
    #[error("Identifier not found")]
    NotFound,
    #[error("Identifier with DID ID {0} not found")]
    NotFoundByDidId(uuid::Uuid),
}

impl IdentifierError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::NotFound => ErrorCode::BR_0207,
            Self::NotFoundByDidId(_) => ErrorCode::BR_0207,
        }
    }
}

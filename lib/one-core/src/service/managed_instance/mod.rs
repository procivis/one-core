use std::sync::Arc;

use crate::config::core_config;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::clock::Clock;
use crate::proto::http_client::HttpClient;
use crate::proto::session_provider::SessionProvider;
use crate::proto::transaction_manager::TransactionManager;
use crate::provider::document_signer::provider::DocumentSignerProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::signer::provider::SignerProvider;
use crate::provider::verifier::provider::VerifierProvider;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::managed_instance_repository::ManagedInstanceRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::trust_collection_repository::TrustCollectionRepository;

pub mod dto;
pub mod error;
pub mod service;
mod validator;

mod app_integrity;
pub(crate) mod ecosystem_metadata;
mod mapper;
#[cfg(test)]
mod test;

#[derive(Clone)]
pub struct ManagedInstanceService {
    organisation_repository: Arc<dyn OrganisationRepository>,
    wallet_instance_repository: Arc<dyn ManagedInstanceRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    trust_collection_repository: Arc<dyn TrustCollectionRepository>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    tx_manager: Arc<dyn TransactionManager>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    signer_provider: Arc<dyn SignerProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    http_client: Arc<dyn HttpClient>,
    clock: Arc<dyn Clock>,
    session_provider: Arc<dyn SessionProvider>,
    document_signer_provider: Arc<dyn DocumentSignerProvider>,
    verifier_provider: Arc<dyn VerifierProvider>,
    base_url: Option<String>,
    config: Arc<core_config::CoreConfig>,
}

impl ManagedInstanceService {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        organisation_repository: Arc<dyn OrganisationRepository>,
        wallet_instance_repository: Arc<dyn ManagedInstanceRepository>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        trust_collection_repository: Arc<dyn TrustCollectionRepository>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        tx_manager: Arc<dyn TransactionManager>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        signer_provider: Arc<dyn SignerProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        http_client: Arc<dyn HttpClient>,
        clock: Arc<dyn Clock>,
        session_provider: Arc<dyn SessionProvider>,
        document_signer_provider: Arc<dyn DocumentSignerProvider>,
        verifier_provider: Arc<dyn VerifierProvider>,
        config: Arc<core_config::CoreConfig>,
        base_url: Option<String>,
    ) -> Self {
        Self {
            organisation_repository,
            wallet_instance_repository,
            identifier_repository,
            history_repository,
            trust_collection_repository,
            credential_schema_repository,
            tx_manager,
            key_provider,
            key_algorithm_provider,
            revocation_method_provider,
            signer_provider,
            certificate_validator,
            http_client,
            config,
            base_url,
            clock,
            session_provider,
            document_signer_provider,
            verifier_provider,
        }
    }
}

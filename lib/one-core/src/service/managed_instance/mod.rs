use std::sync::Arc;

use crate::config::core_config;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::http_client::HttpClient;
use crate::proto::session_provider::SessionProvider;
use crate::proto::transaction_manager::TransactionManager;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::signer::provider::SignerProvider;
use crate::provider::verifier::provider::VerifierProvider;
use crate::provider::wallet::provider::WalletProviderDirectory;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::managed_instance_repository::ManagedInstanceRepository;
use crate::repository::organisation_repository::OrganisationRepository;

pub mod dto;
pub mod error;
pub mod service;
pub(crate) mod validator;

mod app_integrity;
pub(crate) mod ecosystem_metadata;
pub(crate) mod mapper;
#[cfg(test)]
mod test;

#[derive(Clone)]
pub struct ManagedInstanceService {
    organisation_repository: Arc<dyn OrganisationRepository>,
    managed_instance_repository: Arc<dyn ManagedInstanceRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    tx_manager: Arc<dyn TransactionManager>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    signer_provider: Arc<dyn SignerProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    http_client: Arc<dyn HttpClient>,
    session_provider: Arc<dyn SessionProvider>,
    verifier_provider: Arc<dyn VerifierProvider>,
    wallet_provider_directory: Arc<dyn WalletProviderDirectory>,
    base_url: Option<String>,
    config: Arc<core_config::CoreConfig>,
}

impl ManagedInstanceService {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        organisation_repository: Arc<dyn OrganisationRepository>,
        managed_instance_repository: Arc<dyn ManagedInstanceRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        tx_manager: Arc<dyn TransactionManager>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        signer_provider: Arc<dyn SignerProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        http_client: Arc<dyn HttpClient>,
        session_provider: Arc<dyn SessionProvider>,
        verifier_provider: Arc<dyn VerifierProvider>,
        wallet_provider_directory: Arc<dyn WalletProviderDirectory>,
        config: Arc<core_config::CoreConfig>,
        base_url: Option<String>,
    ) -> Self {
        Self {
            organisation_repository,
            managed_instance_repository,
            history_repository,
            tx_manager,
            key_algorithm_provider,
            revocation_method_provider,
            signer_provider,
            certificate_validator,
            http_client,
            config,
            base_url,
            session_provider,
            verifier_provider,
            wallet_provider_directory,
        }
    }
}

pub mod dto;
pub mod error;
pub mod service;
mod validator;

mod app_integrity;
mod mapper;
#[cfg(test)]
mod test;

use std::sync::Arc;

use crate::config::core_config;
use crate::proto::session_provider::SessionProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::wallet_unit_repository::WalletUnitRepository;
use crate::service::certificate::validator::CertificateValidator;
use crate::util::clock::Clock;

#[allow(dead_code)]
#[derive(Clone)]
pub struct SSIWalletProviderService {
    organisation_repository: Arc<dyn OrganisationRepository>,
    wallet_unit_repository: Arc<dyn WalletUnitRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    clock: Arc<dyn Clock>,
    session_provider: Arc<dyn SessionProvider>,
    base_url: Option<String>,
    config: Arc<core_config::CoreConfig>,
}

impl SSIWalletProviderService {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        organisation_repository: Arc<dyn OrganisationRepository>,
        wallet_unit_repository: Arc<dyn WalletUnitRepository>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        clock: Arc<dyn Clock>,
        session_provider: Arc<dyn SessionProvider>,
        config: Arc<core_config::CoreConfig>,
        base_url: Option<String>,
    ) -> Self {
        Self {
            organisation_repository,
            wallet_unit_repository,
            identifier_repository,
            history_repository,
            key_provider,
            key_algorithm_provider,
            certificate_validator,
            config,
            base_url,
            clock,
            session_provider,
        }
    }
}

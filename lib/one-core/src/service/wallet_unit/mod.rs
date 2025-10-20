use std::sync::Arc;

use crate::config::core_config::CoreConfig;
use crate::proto::session_provider::SessionProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::os_provider::OSInfoProvider;
use crate::provider::wallet_provider_client::WalletProviderClient;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::wallet_unit_attestation_repository::WalletUnitAttestationRepository;
use crate::util::clock::Clock;

pub mod dto;
pub mod error;
pub mod service;

mod mapper;
#[cfg(test)]
mod test;

#[derive(Clone)]
pub struct WalletUnitService {
    key_repository: Arc<dyn KeyRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    wallet_unit_attestation_repository: Arc<dyn WalletUnitAttestationRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    wallet_provider_client: Arc<dyn WalletProviderClient>,
    os_info_provider: Arc<dyn OSInfoProvider>,
    clock: Arc<dyn Clock>,
    base_url: Option<String>,
    config: Arc<CoreConfig>,
    session_provider: Arc<dyn SessionProvider>,
}

impl WalletUnitService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organisation_repository: Arc<dyn OrganisationRepository>,
        wallet_unit_attestation_repository: Arc<dyn WalletUnitAttestationRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        key_repository: Arc<dyn KeyRepository>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        wallet_provider_client: Arc<dyn WalletProviderClient>,
        os_info_provider: Arc<dyn OSInfoProvider>,
        clock: Arc<dyn Clock>,
        base_url: Option<String>,
        config: Arc<CoreConfig>,
        session_provider: Arc<dyn SessionProvider>,
    ) -> Self {
        Self {
            wallet_provider_client,
            key_provider,
            key_repository,
            key_algorithm_provider,
            os_info_provider,
            organisation_repository,
            wallet_unit_attestation_repository,
            history_repository,
            clock,
            base_url,
            config,
            session_provider,
        }
    }
}

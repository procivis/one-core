pub mod dto;
pub mod error;
pub mod service;
mod validator;

#[cfg(test)]
mod test;

use std::sync::Arc;

use crate::config::core_config;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::wallet_unit_repository::WalletUnitRepository;
use crate::util::clock::Clock;

#[allow(dead_code)]
#[derive(Clone)]
pub struct SSIWalletProviderService {
    wallet_unit_repository: Arc<dyn WalletUnitRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    clock: Arc<dyn Clock>,
    base_url: Option<String>,
    config: Arc<core_config::CoreConfig>,
}

impl SSIWalletProviderService {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        wallet_unit_repository: Arc<dyn WalletUnitRepository>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        clock: Arc<dyn Clock>,
        config: Arc<core_config::CoreConfig>,
        base_url: Option<String>,
    ) -> Self {
        Self {
            wallet_unit_repository,
            identifier_repository,
            history_repository,
            key_provider,
            key_algorithm_provider,
            config,
            base_url,
            clock,
        }
    }
}

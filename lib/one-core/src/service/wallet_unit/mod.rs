use std::sync::Arc;

use crate::config::core_config::CoreConfig;
use crate::proto::clock::Clock;
use crate::proto::os_provider::OSInfoProvider;
use crate::proto::session_provider::SessionProvider;
use crate::proto::transaction_manager::TransactionManager;
use crate::proto::trust_collection::TrustCollectionManager;
use crate::proto::trust_list_subscription_sync::TrustListSubscriptionSync;
use crate::proto::wallet_provider_client::WalletProviderClient;
use crate::proto::wallet_unit::HolderWalletUnitProto;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::holder_wallet_unit_repository::HolderWalletUnitRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::trust_collection_repository::TrustCollectionRepository;
use crate::repository::trust_list_subscription_repository::TrustListSubscriptionRepository;

pub mod dto;
pub mod error;
pub(crate) mod mapper;
pub mod service;
#[cfg(test)]
mod test;

#[derive(Clone)]
pub struct WalletUnitService {
    key_repository: Arc<dyn KeyRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    holder_wallet_unit_repository: Arc<dyn HolderWalletUnitRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    wallet_provider_client: Arc<dyn WalletProviderClient>,
    wallet_unit_proto: Arc<dyn HolderWalletUnitProto>,
    os_info_provider: Arc<dyn OSInfoProvider>,
    trust_collection_manager: Arc<dyn TrustCollectionManager>,
    trust_list_subscription_sync: Arc<dyn TrustListSubscriptionSync>,
    trust_collection_repository: Arc<dyn TrustCollectionRepository>,
    trust_subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
    tx_manager: Arc<dyn TransactionManager>,
    clock: Arc<dyn Clock>,
    base_url: Option<String>,
    config: Arc<CoreConfig>,
    session_provider: Arc<dyn SessionProvider>,
}

impl WalletUnitService {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        organisation_repository: Arc<dyn OrganisationRepository>,
        holder_wallet_unit_repository: Arc<dyn HolderWalletUnitRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        key_repository: Arc<dyn KeyRepository>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        wallet_provider_client: Arc<dyn WalletProviderClient>,
        wallet_unit_proto: Arc<dyn HolderWalletUnitProto>,
        os_info_provider: Arc<dyn OSInfoProvider>,
        trust_collection_manager: Arc<dyn TrustCollectionManager>,
        trust_list_subscription_sync: Arc<dyn TrustListSubscriptionSync>,
        trust_collection_repository: Arc<dyn TrustCollectionRepository>,
        trust_subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
        tx_manager: Arc<dyn TransactionManager>,
        clock: Arc<dyn Clock>,
        base_url: Option<String>,
        config: Arc<CoreConfig>,
        session_provider: Arc<dyn SessionProvider>,
    ) -> Self {
        Self {
            wallet_provider_client,
            wallet_unit_proto,
            key_provider,
            key_repository,
            key_algorithm_provider,
            os_info_provider,
            trust_collection_manager,
            trust_list_subscription_sync,
            trust_collection_repository,
            trust_subscription_repository,
            tx_manager,
            organisation_repository,
            holder_wallet_unit_repository,
            history_repository,
            clock,
            base_url,
            config,
            session_provider,
        }
    }
}

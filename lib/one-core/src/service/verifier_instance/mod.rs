use std::sync::Arc;

use crate::proto::session_provider::SessionProvider;
use crate::proto::transaction_manager::TransactionManager;
use crate::proto::trust_collection::TrustCollectionManager;
use crate::proto::trust_list_subscription_sync::TrustListSubscriptionSync;
use crate::proto::verifier_provider_client::VerifierProviderClient;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::trust_collection_repository::TrustCollectionRepository;
use crate::repository::trust_list_subscription_repository::TrustListSubscriptionRepository;
use crate::repository::verifier_instance_repository::VerifierInstanceRepository;

pub mod dto;
pub mod error;
pub mod service;
#[cfg(test)]
mod test;

#[derive(Clone)]
pub struct VerifierInstanceService {
    organisation_repository: Arc<dyn OrganisationRepository>,
    verifier_instance_repository: Arc<dyn VerifierInstanceRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    verifier_provider_client: Arc<dyn VerifierProviderClient>,
    trust_collection_manager: Arc<dyn TrustCollectionManager>,
    trust_collection_repository: Arc<dyn TrustCollectionRepository>,
    trust_subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
    trust_list_subscription_sync: Arc<dyn TrustListSubscriptionSync>,
    tx_manager: Arc<dyn TransactionManager>,
    session_provider: Arc<dyn SessionProvider>,
}

impl VerifierInstanceService {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        organisation_repository: Arc<dyn OrganisationRepository>,
        verifier_instance_repository: Arc<dyn VerifierInstanceRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        verifier_provider_client: Arc<dyn VerifierProviderClient>,
        trust_collection_manager: Arc<dyn TrustCollectionManager>,
        trust_collection_repository: Arc<dyn TrustCollectionRepository>,
        trust_subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
        trust_list_subscription_sync: Arc<dyn TrustListSubscriptionSync>,
        tx_manager: Arc<dyn TransactionManager>,
        session_provider: Arc<dyn SessionProvider>,
    ) -> Self {
        Self {
            trust_collection_manager,
            trust_collection_repository,
            trust_subscription_repository,
            trust_list_subscription_sync,
            tx_manager,
            organisation_repository,
            verifier_instance_repository,
            history_repository,
            session_provider,
            verifier_provider_client,
        }
    }
}

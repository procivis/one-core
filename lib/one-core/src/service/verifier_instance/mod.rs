use std::sync::Arc;

use crate::proto::session_provider::SessionProvider;
use crate::proto::transaction_manager::TransactionManager;
use crate::proto::trust_collection::TrustCollectionManager;
use crate::proto::verifier_provider_client::VerifierProviderClient;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::organisation_repository::OrganisationRepository;
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
    tx_manager: Arc<dyn TransactionManager>,
    session_provider: Arc<dyn SessionProvider>,
}

impl VerifierInstanceService {
    pub(crate) fn new(
        organisation_repository: Arc<dyn OrganisationRepository>,
        verifier_instance_repository: Arc<dyn VerifierInstanceRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        verifier_provider_client: Arc<dyn VerifierProviderClient>,
        trust_collection_manager: Arc<dyn TrustCollectionManager>,
        tx_manager: Arc<dyn TransactionManager>,
        session_provider: Arc<dyn SessionProvider>,
    ) -> Self {
        Self {
            trust_collection_manager,
            tx_manager,
            organisation_repository,
            verifier_instance_repository,
            history_repository,
            session_provider,
            verifier_provider_client,
        }
    }
}

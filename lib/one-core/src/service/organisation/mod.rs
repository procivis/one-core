use std::sync::Arc;

use crate::config::core_config::CoreConfig;
use crate::proto::ecosystem_sync::EcosystemSync;
use crate::proto::trust_list_subscription_sync::TrustListSubscriptionSync;
use crate::proto::verifier_provider_client::VerifierProviderClient;
use crate::proto::wallet_provider_client::WalletProviderClient;
use crate::provider::verifier::provider::VerifierProviderDirectory;
use crate::provider::wallet::provider::WalletProviderDirectory;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::instance_repository::InstanceRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::trust_collection_repository::TrustCollectionRepository;
use crate::repository::trust_list_subscription_repository::TrustListSubscriptionRepository;

pub mod dto;
pub mod error;
mod mapper;
pub mod service;

#[derive(Clone)]
pub struct OrganisationService {
    organisation_repository: Arc<dyn OrganisationRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    instance_repository: Arc<dyn InstanceRepository>,
    wallet_provider_client: Arc<dyn WalletProviderClient>,
    verifier_provider_client: Arc<dyn VerifierProviderClient>,
    trust_list_subscription_sync: Arc<dyn TrustListSubscriptionSync>,
    trust_collection_repository: Arc<dyn TrustCollectionRepository>,
    trust_subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
    wallet_provider_directory: Arc<dyn WalletProviderDirectory>,
    verifier_provider_directory: Arc<dyn VerifierProviderDirectory>,
    ecosystem_sync: Arc<dyn EcosystemSync>,
    core_config: Arc<CoreConfig>,
}

impl OrganisationService {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        organisation_repository: Arc<dyn OrganisationRepository>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        instance_repository: Arc<dyn InstanceRepository>,
        wallet_provider_client: Arc<dyn WalletProviderClient>,
        verifier_provider_client: Arc<dyn VerifierProviderClient>,
        trust_list_subscription_sync: Arc<dyn TrustListSubscriptionSync>,
        trust_collection_repository: Arc<dyn TrustCollectionRepository>,
        trust_subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
        wallet_provider_directory: Arc<dyn WalletProviderDirectory>,
        verifier_provider_directory: Arc<dyn VerifierProviderDirectory>,
        ecosystem_sync: Arc<dyn EcosystemSync>,
        core_config: Arc<CoreConfig>,
    ) -> Self {
        Self {
            organisation_repository,
            identifier_repository,
            instance_repository,
            wallet_provider_client,
            verifier_provider_client,
            trust_list_subscription_sync,
            trust_collection_repository,
            trust_subscription_repository,
            wallet_provider_directory,
            verifier_provider_directory,
            ecosystem_sync,
            core_config,
        }
    }
}

#[cfg(test)]
mod test;
mod validator;

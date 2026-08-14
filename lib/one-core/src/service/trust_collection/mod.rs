use std::sync::Arc;

use crate::proto::session_provider::SessionProvider;
use crate::provider::ecosystem::directory::EcosystemDirectory;
use crate::provider::trust_list_subscriber::provider::TrustListSubscriberProvider;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::trust_collection_repository::TrustCollectionRepository;
use crate::repository::trust_list_subscription_repository::TrustListSubscriptionRepository;

pub mod dto;
pub mod error;
mod mapper;
pub mod service;
#[cfg(test)]
mod test;

#[derive(Clone)]
pub struct TrustCollectionService {
    organisation_repository: Arc<dyn OrganisationRepository>,
    trust_collection_repository: Arc<dyn TrustCollectionRepository>,
    trust_list_subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
    trust_list_subscriber_provider: Arc<dyn TrustListSubscriberProvider>,
    session_provider: Arc<dyn SessionProvider>,
    ecosystem_provider: Arc<dyn EcosystemDirectory>,
}

impl TrustCollectionService {
    pub(crate) fn new(
        organisation_repository: Arc<dyn OrganisationRepository>,
        trust_collection_repository: Arc<dyn TrustCollectionRepository>,
        trust_list_subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
        trust_list_subscriber_provider: Arc<dyn TrustListSubscriberProvider>,
        session_provider: Arc<dyn SessionProvider>,
        ecosystem_provider: Arc<dyn EcosystemDirectory>,
    ) -> Self {
        Self {
            organisation_repository,
            trust_collection_repository,
            trust_list_subscription_repository,
            trust_list_subscriber_provider,
            session_provider,
            ecosystem_provider,
        }
    }
}

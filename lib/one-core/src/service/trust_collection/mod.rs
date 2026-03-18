use std::sync::Arc;

use crate::proto::clock::Clock;
use crate::proto::session_provider::SessionProvider;
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
    trust_collection_repository: Arc<dyn TrustCollectionRepository>,
    trust_list_subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
    session_provider: Arc<dyn SessionProvider>,
    clock: Arc<dyn Clock>,
}

impl TrustCollectionService {
    pub(crate) fn new(
        trust_collection_repository: Arc<dyn TrustCollectionRepository>,
        trust_list_subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
        session_provider: Arc<dyn SessionProvider>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            trust_collection_repository,
            trust_list_subscription_repository,
            session_provider,
            clock,
        }
    }
}

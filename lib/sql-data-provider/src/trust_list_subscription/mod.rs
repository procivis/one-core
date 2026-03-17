use std::sync::Arc;

use one_core::repository::trust_collection_repository::TrustCollectionRepository;

use crate::transaction_context::TransactionManagerImpl;

mod mapper;
mod repository;
#[cfg(test)]
mod test;

pub(crate) struct TrustListSubscriptionProvider {
    pub db: TransactionManagerImpl,
    pub trust_collection_repository: Arc<dyn TrustCollectionRepository>,
}

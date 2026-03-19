use std::sync::Arc;

use crate::proto::clock::Clock;
use crate::proto::session_provider::SessionProvider;
use crate::repository::trust_collection_repository::TrustCollectionRepository;

pub mod dto;
pub mod error;
pub mod service;
#[cfg(test)]
mod test;

#[derive(Clone)]
pub struct TrustCollectionService {
    trust_collection_repository: Arc<dyn TrustCollectionRepository>,
    session_provider: Arc<dyn SessionProvider>,
    clock: Arc<dyn Clock>,
}

impl TrustCollectionService {
    pub(crate) fn new(
        trust_collection_repository: Arc<dyn TrustCollectionRepository>,
        session_provider: Arc<dyn SessionProvider>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            trust_collection_repository,
            session_provider,
            clock,
        }
    }
}

use std::sync::Arc;

use crate::proto::session_provider::SessionProvider;
use crate::provider::trust_list_publisher::provider::TrustListPublisherProvider;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::trust_entry_repository::TrustEntryRepository;
use crate::repository::trust_list_publication_repository::TrustListPublicationRepository;

pub mod dto;
pub mod error;
pub mod service;

#[derive(Clone)]
pub struct TrustListPublicationService {
    identifier_repository: Arc<dyn IdentifierRepository>,
    trust_list_publication_repository: Arc<dyn TrustListPublicationRepository>,
    trust_entry_repository: Arc<dyn TrustEntryRepository>,
    session_provider: Arc<dyn SessionProvider>,
    trust_list_publisher_provider: Arc<dyn TrustListPublisherProvider>,
}

impl TrustListPublicationService {
    pub(crate) fn new(
        identifier_repository: Arc<dyn IdentifierRepository>,
        trust_list_publication_repository: Arc<dyn TrustListPublicationRepository>,
        trust_entry_repository: Arc<dyn TrustEntryRepository>,
        session_provider: Arc<dyn SessionProvider>,
        trust_list_publisher_provider: Arc<dyn TrustListPublisherProvider>,
    ) -> Self {
        Self {
            identifier_repository,
            trust_list_publication_repository,
            trust_entry_repository,
            session_provider,
            trust_list_publisher_provider,
        }
    }
}

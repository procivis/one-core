use std::sync::Arc;

use one_core::repository::identifier_repository::IdentifierRepository;
use one_core::repository::trust_list_publication_repository::TrustListPublicationRepository;

use crate::transaction_context::TransactionManagerImpl;

mod mapper;
mod repository;

#[cfg(test)]
mod test;

pub(crate) struct TrustEntryProvider {
    pub db: TransactionManagerImpl,
    pub trust_list_publication_repository: Arc<dyn TrustListPublicationRepository>,
    pub identifier_repository: Arc<dyn IdentifierRepository>,
}

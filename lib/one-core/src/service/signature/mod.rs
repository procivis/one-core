use std::sync::Arc;

use crate::proto::session_provider::SessionProvider;
use crate::provider::signer::provider::SignerProvider;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;

pub mod dto;
mod error;
mod mapper;
pub mod service;

#[derive(Clone)]
pub struct SignatureService {
    signer_provider: Arc<dyn SignerProvider>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    history: Arc<dyn HistoryRepository>,
    session_provider: Arc<dyn SessionProvider>,
}

impl SignatureService {
    pub(crate) fn new(
        signer_provider: Arc<dyn SignerProvider>,
        revocation_list_repository: Arc<dyn RevocationListRepository>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        history: Arc<dyn HistoryRepository>,
        session_provider: Arc<dyn SessionProvider>,
    ) -> Self {
        Self {
            signer_provider,
            revocation_list_repository,
            identifier_repository,
            history,
            session_provider,
        }
    }
}

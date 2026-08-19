use std::sync::Arc;

use crate::proto::session_provider::SessionProvider;
use crate::provider::document_signer::provider::DocumentSignerProvider;
use crate::repository::history_repository::HistoryRepository;

pub mod dto;
pub mod error;
pub mod service;

#[derive(Clone)]
pub struct QesService {
    document_signer_provider: Arc<dyn DocumentSignerProvider>,
    history_repository: Arc<dyn HistoryRepository>,
    session_provider: Arc<dyn SessionProvider>,
}

impl QesService {
    pub(crate) fn new(
        document_signer_provider: Arc<dyn DocumentSignerProvider>,
        history_repository: Arc<dyn HistoryRepository>,
        session_provider: Arc<dyn SessionProvider>,
    ) -> Self {
        Self {
            document_signer_provider,
            history_repository,
            session_provider,
        }
    }
}

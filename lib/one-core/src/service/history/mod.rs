use std::sync::Arc;

use crate::proto::session_provider::SessionProvider;
use crate::repository::history_repository::HistoryRepository;

pub mod dto;
pub mod service;

pub(crate) mod mapper;

#[derive(Clone)]
pub struct HistoryService {
    history_repository: Arc<dyn HistoryRepository>,
    session_provider: Arc<dyn SessionProvider>,
}

impl HistoryService {
    pub fn new(
        history_repository: Arc<dyn HistoryRepository>,
        session_provider: Arc<dyn SessionProvider>,
    ) -> Self {
        Self {
            history_repository,
            session_provider,
        }
    }
}

#[cfg(test)]
mod test;

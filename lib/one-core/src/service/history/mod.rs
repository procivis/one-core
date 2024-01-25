use std::sync::Arc;

use crate::repository::history_repository::HistoryRepository;

pub mod dto;
pub mod service;

pub(crate) mod mapper;

#[derive(Clone)]
pub struct HistoryService {
    history_repository: Arc<dyn HistoryRepository>,
}

impl HistoryService {
    pub fn new(history_repository: Arc<dyn HistoryRepository>) -> Self {
        Self { history_repository }
    }
}

#[cfg(test)]
mod test;

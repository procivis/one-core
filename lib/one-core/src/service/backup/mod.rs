use std::sync::Arc;

use crate::repository::{
    backup_repository::BackupRepository, history_repository::HistoryRepository,
    organisation_repository::OrganisationRepository,
};

pub mod dto;
pub mod service;
mod utils;

#[derive(Clone)]
pub struct BackupService {
    backup_repository: Arc<dyn BackupRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
}

#[cfg(test)]
mod test;

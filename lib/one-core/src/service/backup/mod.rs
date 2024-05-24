use std::sync::Arc;

use crate::repository::backup_repository::BackupRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::organisation_repository::OrganisationRepository;

pub mod dto;
pub mod service;
mod utils;

#[derive(Clone)]
pub struct BackupService {
    backup_repository: Arc<dyn BackupRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
}

impl BackupService {
    pub fn new(
        backup_repository: Arc<dyn BackupRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
    ) -> Self {
        Self {
            backup_repository,
            history_repository,
            organisation_repository,
        }
    }
}

#[cfg(test)]
mod test;

use std::sync::Arc;

use crate::config::core_config::CoreConfig;
use crate::repository::backup_repository::BackupRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::organisation_repository::OrganisationRepository;

pub mod dto;
mod mapper;
pub mod service;
mod utils;

#[derive(Clone)]
pub struct BackupService {
    backup_repository: Arc<dyn BackupRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    config: Arc<CoreConfig>,
}

impl BackupService {
    pub fn new(
        backup_repository: Arc<dyn BackupRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        config: Arc<CoreConfig>,
    ) -> Self {
        Self {
            backup_repository,
            history_repository,
            organisation_repository,
            config,
        }
    }
}

#[cfg(test)]
mod test;

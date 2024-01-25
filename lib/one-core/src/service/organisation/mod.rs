use std::sync::Arc;

use crate::repository::{
    history_repository::HistoryRepository, organisation_repository::OrganisationRepository,
};

pub mod dto;
pub mod mapper;
pub mod service;
pub mod validator;

#[derive(Clone)]
pub struct OrganisationService {
    history_repository: Arc<dyn HistoryRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
}

impl OrganisationService {
    pub fn new(
        organisation_repository: Arc<dyn OrganisationRepository>,
        history_repository: Arc<dyn HistoryRepository>,
    ) -> Self {
        Self {
            history_repository,
            organisation_repository,
        }
    }
}

#[cfg(test)]
mod test;

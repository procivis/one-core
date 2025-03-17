use std::sync::Arc;

use crate::repository::organisation_repository::OrganisationRepository;

pub mod dto;
mod mapper;
pub mod service;
#[derive(Clone)]
pub struct OrganisationService {
    organisation_repository: Arc<dyn OrganisationRepository>,
}

impl OrganisationService {
    pub fn new(organisation_repository: Arc<dyn OrganisationRepository>) -> Self {
        Self {
            organisation_repository,
        }
    }
}

#[cfg(test)]
mod test;

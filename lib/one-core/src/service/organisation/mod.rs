use std::sync::Arc;

use crate::repository::organisation_repository::OrganisationRepository;

pub mod dto;
pub mod service;
pub mod validator;

#[derive(Clone)]
pub struct OrganisationService {
    organisation_repository: Arc<dyn OrganisationRepository>,
}

impl OrganisationService {
    pub fn new(repository: Arc<dyn OrganisationRepository>) -> Self {
        Self {
            organisation_repository: repository,
        }
    }
}

#[cfg(test)]
mod test;

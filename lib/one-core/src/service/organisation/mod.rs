use std::sync::Arc;

use crate::repository::organisation_repository::OrganisationRepository;

pub mod dto;
pub mod service;
pub mod validator;

pub(crate) mod mapper;

#[derive(Clone)]
pub struct OrganisationService {
    organisation_repository: Arc<dyn OrganisationRepository + Send + Sync>,
}

impl OrganisationService {
    pub fn new(repository: Arc<dyn OrganisationRepository + Send + Sync>) -> Self {
        Self {
            organisation_repository: repository,
        }
    }
}

#[cfg(test)]
mod test;

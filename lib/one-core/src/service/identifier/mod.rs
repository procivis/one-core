use std::sync::Arc;

use super::error::ErrorCode;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::service::did::DidService;

pub mod dto;
pub(crate) mod mapper;
pub mod service;

#[derive(Clone)]
pub struct IdentifierService {
    identifier_repository: Arc<dyn IdentifierRepository>,
    key_repository: Arc<dyn KeyRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,

    did_service: DidService,
}

impl IdentifierService {
    pub fn new(
        identifier_repository: Arc<dyn IdentifierRepository>,
        key_repository: Arc<dyn KeyRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        did_service: DidService,
    ) -> Self {
        Self {
            identifier_repository,
            key_repository,
            organisation_repository,
            did_service,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum IdentifierError {
    #[error("Identifier not found")]
    NotFound,
    #[error("Identifier with DID ID {0} not found")]
    NotFoundByDidId(uuid::Uuid),
}

impl IdentifierError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::NotFound => ErrorCode::BR_0207,
            Self::NotFoundByDidId(_) => ErrorCode::BR_0207,
        }
    }
}

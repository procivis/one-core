use std::sync::Arc;

use super::error::ErrorCode;
use crate::config::core_config;
use crate::proto::identifier_creator::IdentifierCreator;
use crate::proto::session_provider::SessionProvider;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::organisation_repository::OrganisationRepository;

pub mod dto;
pub(crate) mod mapper;
pub mod service;
#[cfg(test)]
mod test;
mod validator;

#[derive(Clone)]
pub struct IdentifierService {
    identifier_repository: Arc<dyn IdentifierRepository>,
    key_repository: Arc<dyn KeyRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    config: Arc<core_config::CoreConfig>,
    identifier_creator: Arc<dyn IdentifierCreator>,
    session_provider: Arc<dyn SessionProvider>,
}

impl IdentifierService {
    pub(crate) fn new(
        identifier_repository: Arc<dyn IdentifierRepository>,
        key_repository: Arc<dyn KeyRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        identifier_creator: Arc<dyn IdentifierCreator>,
        config: Arc<core_config::CoreConfig>,
        session_provider: Arc<dyn SessionProvider>,
    ) -> Self {
        Self {
            identifier_repository,
            key_repository,
            organisation_repository,
            identifier_creator,
            config,
            session_provider,
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

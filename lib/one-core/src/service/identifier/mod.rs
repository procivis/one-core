use std::sync::Arc;

use super::error::ErrorCode;
use crate::config::core_config;
use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::service::certificate::CertificateService;
use crate::service::did::DidService;

pub mod dto;
pub(crate) mod mapper;
pub mod service;
mod validator;

#[derive(Clone)]
pub struct IdentifierService {
    identifier_repository: Arc<dyn IdentifierRepository>,
    key_repository: Arc<dyn KeyRepository>,
    certificate_repository: Arc<dyn CertificateRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    config: Arc<core_config::CoreConfig>,

    did_service: DidService,
    certificate_service: CertificateService,
}

impl IdentifierService {
    pub fn new(
        identifier_repository: Arc<dyn IdentifierRepository>,
        key_repository: Arc<dyn KeyRepository>,
        certificate_repository: Arc<dyn CertificateRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        did_service: DidService,
        certificate_service: CertificateService,
        config: Arc<core_config::CoreConfig>,
    ) -> Self {
        Self {
            identifier_repository,
            key_repository,
            certificate_repository,
            organisation_repository,
            did_service,
            certificate_service,
            config,
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

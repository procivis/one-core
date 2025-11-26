use std::sync::Arc;

use super::error::ErrorCode;
use crate::config::core_config;
use crate::proto::session_provider::SessionProvider;
use crate::proto::transaction_manager::TransactionManager;
use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::service::certificate::CertificateService;
use crate::service::did::DidService;

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
    certificate_repository: Arc<dyn CertificateRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    config: Arc<core_config::CoreConfig>,

    did_service: DidService,
    certificate_service: CertificateService,
    session_provider: Arc<dyn SessionProvider>,
    tx_manager: Arc<dyn TransactionManager>,
}

impl IdentifierService {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        identifier_repository: Arc<dyn IdentifierRepository>,
        key_repository: Arc<dyn KeyRepository>,
        certificate_repository: Arc<dyn CertificateRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        did_service: DidService,
        certificate_service: CertificateService,
        config: Arc<core_config::CoreConfig>,
        session_provider: Arc<dyn SessionProvider>,
        tx_manager: Arc<dyn TransactionManager>,
    ) -> Self {
        Self {
            identifier_repository,
            key_repository,
            certificate_repository,
            organisation_repository,
            did_service,
            certificate_service,
            config,
            session_provider,
            tx_manager,
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

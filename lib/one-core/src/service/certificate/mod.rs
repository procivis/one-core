use std::sync::Arc;

use crate::proto::session_provider::SessionProvider;
use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::identifier_repository::IdentifierRepository;

pub mod dto;
pub(crate) mod mapper;
pub mod service;

#[cfg(test)]
mod test;

#[derive(Clone)]
pub struct CertificateService {
    certificate_repository: Arc<dyn CertificateRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    session_provider: Arc<dyn SessionProvider>,
}

impl CertificateService {
    pub(crate) fn new(
        certificate_repository: Arc<dyn CertificateRepository>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        session_provider: Arc<dyn SessionProvider>,
    ) -> Self {
        Self {
            certificate_repository,
            identifier_repository,
            session_provider,
        }
    }
}

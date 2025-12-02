use std::sync::Arc;

use crate::proto::session_provider::SessionProvider;
use crate::repository::certificate_repository::CertificateRepository;

pub mod dto;
pub(crate) mod mapper;
pub mod service;

#[cfg(test)]
mod test;

#[derive(Clone)]
pub struct CertificateService {
    certificate_repository: Arc<dyn CertificateRepository>,
    session_provider: Arc<dyn SessionProvider>,
}

impl CertificateService {
    pub(crate) fn new(
        certificate_repository: Arc<dyn CertificateRepository>,
        session_provider: Arc<dyn SessionProvider>,
    ) -> Self {
        Self {
            certificate_repository,
            session_provider,
        }
    }
}

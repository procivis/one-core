use std::sync::Arc;

use validator::CertificateValidator;

use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::key_repository::KeyRepository;

pub mod dto;
pub(crate) mod mapper;
pub mod service;
pub mod validator;

#[derive(Clone)]
pub struct CertificateService {
    certificate_repository: Arc<dyn CertificateRepository>,
    key_repository: Arc<dyn KeyRepository>,
    validator: Arc<dyn CertificateValidator>,
}

impl CertificateService {
    pub(crate) fn new(
        certificate_repository: Arc<dyn CertificateRepository>,
        key_repository: Arc<dyn KeyRepository>,
        validator: Arc<dyn CertificateValidator>,
    ) -> Self {
        Self {
            certificate_repository,
            key_repository,
            validator,
        }
    }
}

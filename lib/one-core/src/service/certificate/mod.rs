use std::sync::Arc;

use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::key_repository::KeyRepository;

pub mod dto;
pub(crate) mod mapper;
pub mod service;

#[derive(Clone)]
pub struct CertificateService {
    certificate_repository: Arc<dyn CertificateRepository>,
    key_repository: Arc<dyn KeyRepository>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
}

impl CertificateService {
    pub fn new(
        certificate_repository: Arc<dyn CertificateRepository>,
        key_repository: Arc<dyn KeyRepository>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    ) -> Self {
        Self {
            certificate_repository,
            key_repository,
            key_algorithm_provider,
        }
    }
}

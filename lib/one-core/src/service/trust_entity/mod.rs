use std::sync::Arc;

use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::http_client::HttpClient;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::trust_management::provider::TrustManagementProvider;
use crate::repository::did_repository::DidRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::trust_anchor_repository::TrustAnchorRepository;
use crate::repository::trust_entity_repository::TrustEntityRepository;
use crate::service::certificate::validator::CertificateValidator;

pub mod dto;
pub mod mapper;
pub mod remote;
pub mod service;

#[cfg(test)]
mod test;

#[derive(Clone)]
pub struct TrustEntityService {
    trust_anchor_repository: Arc<dyn TrustAnchorRepository>,
    trust_entity_repository: Arc<dyn TrustEntityRepository>,
    did_repository: Arc<dyn DidRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    trust_provider: Arc<dyn TrustManagementProvider>,
    key_provider: Arc<dyn KeyProvider>,
    client: Arc<dyn HttpClient>,
    certificate_validator: Arc<dyn CertificateValidator>,
}

impl TrustEntityService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        trust_anchor_repository: Arc<dyn TrustAnchorRepository>,
        trust_entity_repository: Arc<dyn TrustEntityRepository>,
        did_repository: Arc<dyn DidRepository>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        trust_provider: Arc<dyn TrustManagementProvider>,
        key_provider: Arc<dyn KeyProvider>,
        client: Arc<dyn HttpClient>,
        certificate_validator: Arc<dyn CertificateValidator>,
    ) -> Self {
        Self {
            trust_anchor_repository,
            trust_entity_repository,
            did_repository,
            identifier_repository,
            did_method_provider,
            key_algorithm_provider,
            trust_provider,
            key_provider,
            certificate_validator,
            client,
        }
    }
}

use std::sync::Arc;

use crate::provider::http_client::HttpClient;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::service::certificate::dto::CertificateX509AttributesDTO;
use crate::service::error::ServiceError;

pub mod parse;
mod revocation;
mod x509_extension;

#[derive(Clone)]
pub struct ParsedCertificate {
    pub attributes: CertificateX509AttributesDTO,
    pub subject_common_name: Option<String>,
    pub public_key: KeyHandle,
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait CertificateValidator: Send + Sync {
    /// Extract leaf certificate from the provided PEM chain
    /// Optionally validate the chain, each certificate must be:
    /// * not expired
    /// * not revoked
    /// * correctly signed by the parent cert in the chain
    async fn parse_pem_chain(
        &self,
        pem_chain: &[u8],
        validate: bool,
    ) -> Result<ParsedCertificate, ServiceError>;
}

#[derive(Clone)]
pub struct CertificateValidatorImpl {
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    client: Arc<dyn HttpClient>,
}

impl CertificateValidatorImpl {
    pub fn new(
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        client: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            key_algorithm_provider,
            client,
        }
    }
}

use std::sync::Arc;

use crate::model::key::Key;
use crate::provider::http_client::HttpClient;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::service::certificate::dto::CertificateX509AttributesDTO;
use crate::service::error::ServiceError;

pub mod parse;
mod revocation;
mod x509_extension;

#[derive(Clone)]
pub(crate) struct ParsedCertificate {
    pub attributes: CertificateX509AttributesDTO,
    pub subject_common_name: Option<String>,
    #[allow(dead_code)]
    pub public_key: KeyHandle,
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait CertificateValidator: Send + Sync {
    /// Extract leaf certificate from the provided PEM chain
    /// Optionally validate the chain, each certificate must be:
    /// * not expired
    /// * not revoked
    /// * correctly signed by the parent cert in the chain
    async fn parse_pem_chain<'a>(
        &'a self,
        pem_chain: &[u8],
        validate: bool,
        expected_pub_key: Option<&'a Key>,
    ) -> Result<ParsedCertificate, ServiceError>;
}

#[derive(Clone)]
pub(crate) struct CertificateValidatorImpl {
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    client: Arc<dyn HttpClient>,
}

impl CertificateValidatorImpl {
    pub(crate) fn new(
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        client: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            key_algorithm_provider,
            client,
        }
    }
}

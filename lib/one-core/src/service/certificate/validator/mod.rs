use std::sync::Arc;

use crate::model::certificate::CertificateState;
use crate::provider::caching_loader::x509_crl::X509CrlCache;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::service::certificate::dto::CertificateX509AttributesDTO;
use crate::service::error::ServiceError;
use crate::util::clock::Clock;

pub mod parse;
mod revocation;
mod x509_extension;

#[derive(Clone)]
pub struct ParsedCertificate {
    pub attributes: CertificateX509AttributesDTO,
    pub subject_common_name: Option<String>,
    pub subject_key_identifier: Option<String>,
    pub public_key: KeyHandle,
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait CertificateValidator: Send + Sync {
    /// Extract leaf certificate from the provided PEM chain
    /// Optionally validate the chain depending on the options, each certificate must be:
    /// * not expired if `validity_check` is true
    /// * not revoked if `validity_check` is true
    /// * the chain terminates to a root CA if `require_root_termination` is true
    /// * path length is valid if `validate_path_length` is true
    async fn parse_pem_chain(
        &self,
        pem_chain: &[u8],
        validate: CertificateValidationOptions,
    ) -> Result<ParsedCertificate, ServiceError>;

    async fn parse_pem_chain_with_status(
        &self,
        pem_chain: &[u8],
    ) -> Result<(CertificateState, ParsedCertificate), ServiceError>;

    /// Validates the pem_chain starting from a leaf certificate against a ca_chain starting
    /// from an intermediary or root CA.
    /// Returns the parsed lowest level certificate in the CA chain.
    async fn validate_chain_against_ca_chain(
        &self,
        pem_chain: &[u8],
        ca_pem_chain: &[u8],
    ) -> Result<ParsedCertificate, ServiceError>;
}

pub struct CertificateValidationOptions {
    pub require_root_termination: bool,
    pub validate_path_length: bool,
    pub validity_check: bool,
}

impl CertificateValidationOptions {
    /// No validation is performed
    pub fn no_validation() -> Self {
        Self {
            require_root_termination: false,
            validate_path_length: false,
            validity_check: false,
        }
    }

    /// Full validation is performed, each certificate must be:
    /// * not expired
    /// * not revoked
    /// * correctly signed by the parent cert in the chain
    /// * part of a chain that terminates to a root CA
    /// * path length is valid
    pub fn full_validation() -> Self {
        Self {
            require_root_termination: true,
            validate_path_length: true,
            validity_check: true,
        }
    }

    /// Only signature and revocation checks are performed
    pub fn signature_and_revocation() -> Self {
        Self {
            require_root_termination: false,
            validate_path_length: false,
            validity_check: true,
        }
    }
}

#[derive(Clone)]
pub struct CertificateValidatorImpl {
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    crl_cache: Arc<X509CrlCache>,
    clock: Arc<dyn Clock>,
}

impl CertificateValidatorImpl {
    pub fn new(
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        crl_cache: Arc<X509CrlCache>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            key_algorithm_provider,
            crl_cache,
            clock,
        }
    }
}

#[cfg(test)]
mod tests {
    use mockall::predicate::eq;
    use time::Duration;
    use x509_parser::pem::Pem;

    use super::*;
    use crate::provider::caching_loader::x509_crl::X509CrlResolver;
    use crate::provider::http_client::{
        Method, MockHttpClient, Request, RequestBuilder, Response, StatusCode,
    };
    use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
    use crate::provider::remote_entity_storage::MockRemoteEntityStorage;
    use crate::util::clock::DefaultClock;

    #[tokio::test]
    async fn test_revocation_check_uses_crl_cache() {
        const CRL_URL: &str =
            "https://ca.dev.mdl-plus.com/crl/0F483FD3C612F848B2C4DCCBF889A6EA980F5340/";

        const CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----
MIIDajCCAw+gAwIBAgIUPum/ISM/HNf0MmLouI/Xmo2uHpswCgYIKoZIzj0EAwIw
gZYxHDAaBgNVBAMME2NhLmRldi5tZGwtcGx1cy5jb20xCzAJBgNVBAYTAkNIMQ8w
DQYDVQQHDAZadXJpY2gxFDASBgNVBAoMC1Byb2NpdmlzIEFHMR4wHAYDVQQLDBVD
ZXJ0aWZpY2F0ZSBBdXRob3JpdHkxIjAgBgkqhkiG9w0BCQEWE3N1cHBvcnRAcHJv
Y2l2aXMuY2gwHhcNMjUwNjExMTIwNzAwWhcNMjYwNjExMDAwMDAwWjAzMR4wHAYD
VQQDDBVjZXJ0aWZpY2F0ZSB0byByZXZva2UxETAPBgNVBAoMCHByb2NpdmlzMCow
BQYDK2VwAyEAc8e6r5Y37U5taAlxw4vuYvjLze/hkU1+xfCRJHT859WjggHKMIIB
xjAfBgNVHSMEGDAWgBTwRW4F4T4leovcPb2ViJ4f4ydmmTAMBgNVHRMBAf8EAjAA
MB0GA1UdDgQWBBSwK0+7wMMas2ChH9Ohps+4YWoaqjCBygYIKwYBBQUHAQEEgb0w
gbowWwYIKwYBBQUHMAGGT2h0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbS9vY3Nw
LzBGNDgzRkQzQzYxMkY4NDhCMkM0RENDQkY4ODlBNkVBOTgwRjUzNDAvY2VydC8w
WwYIKwYBBQUHMAKGT2h0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbS9pc3N1ZXIv
MEY0ODNGRDNDNjEyRjg0OEIyQzREQ0NCRjg4OUE2RUE5ODBGNTM0MC5kZXIwWgYD
VR0fBFMwUTBPoE2gS4ZJaHR0cHM6Ly9jYS5kZXYubWRsLXBsdXMuY29tL2NybC8w
RjQ4M0ZEM0M2MTJGODQ4QjJDNERDQ0JGODg5QTZFQTk4MEY1MzQwLzAVBgNVHSUB
Af8ECzAJBgcogYxdBQECMCYGA1UdEgQfMB2GG2h0dHBzOi8vY2EuZGV2Lm1kbC1w
bHVzLmNvbTAOBgNVHQ8BAf8EBAMCB4AwCgYIKoZIzj0EAwIDSQAwRgIhAO0Grhcr
ghmzjmJo8DYBQWSKpGl2o7quVEKkUwknf09uAiEAlpyzhFx9iJ+Hgr/ITIv89e7y
STsfRXkSUfgzmbAsuDE=
-----END CERTIFICATE-----";

        let key_algorithm = MockKeyAlgorithmProvider::new();
        let mut mock_http_client = MockHttpClient::new();
        let mut mock_remote_entity_storage = MockRemoteEntityStorage::new();

        // The cache should be checked first
        mock_remote_entity_storage
            .expect_get_by_key()
            .with(eq(CRL_URL))
            .returning(|_| Ok(None));

        // If the cache is empty, the CRL should be downloaded
        mock_http_client
            .expect_get()
            .with(eq(CRL_URL))
            .returning(|_| {
                let mut client = MockHttpClient::new();
                client.expect_send().returning(|_, _, _, _| {
                    Ok(Response {
                        body: vec![],
                        headers: Default::default(),
                        status: StatusCode(404),
                        request: Request {
                            body: None,
                            headers: Default::default(),
                            method: Method::Get,
                            url: CRL_URL.to_owned(),
                        },
                    })
                });

                RequestBuilder::new(Arc::new(client), Method::Get, CRL_URL)
            });

        let validator = CertificateValidatorImpl::new(
            Arc::new(key_algorithm),
            Arc::new(X509CrlCache::new(
                Arc::new(X509CrlResolver::new(Arc::new(mock_http_client))),
                Arc::new(mock_remote_entity_storage),
                100,
                Duration::days(1),
                Duration::days(1),
            )),
            Arc::new(DefaultClock),
        );

        let pem = Pem::iter_from_buffer(CERTIFICATE.as_bytes())
            .next()
            .unwrap()
            .unwrap();

        // The check will fail because we do not provide a mock CRL
        let _error = validator
            .check_revocation(&pem.parse_x509().unwrap(), None)
            .await;
    }
}

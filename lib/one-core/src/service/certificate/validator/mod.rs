use std::sync::Arc;

use crate::provider::caching_loader::android_attestation_crl::AndroidAttestationCrlCache;
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
    /// Optionally validate the chain depending on the options
    async fn parse_pem_chain(
        &self,
        pem_chain: &str,
        validation: CertificateValidationOptions,
    ) -> Result<ParsedCertificate, ServiceError>;

    /// Validates the pem_chain starting from a leaf certificate against a ca_chain starting
    /// from an intermediary or root CA.
    /// Returns the parsed certificate according to the `cert_selection`.
    async fn validate_chain_against_ca_chain(
        &self,
        pem_chain: &str,
        ca_pem_chain: &str,
        validation: CertificateValidationOptions,
        cert_selection: CertSelection,
    ) -> Result<ParsedCertificate, ServiceError>;
}

pub enum CertSelection {
    /// Last certificate in the CA chain
    LowestCaChain,
    /// Leaf certificate of the whole chain
    Leaf,
}

#[derive(Clone, Debug, Copy, Default)]
pub enum CrlMode {
    #[default]
    X509,
    /// <https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status>
    AndroidAttestation,
}

pub enum EnforceKeyUsage {
    DigitalSignature,
}

pub struct CertificateValidationOptions {
    /// will fail if the chain is not complete
    pub require_root_termination: bool,
    /// will fail if the CA path-len limits are violated, a signature doesn't match, or an unknown critical extension is used
    pub integrity_check: bool,
    /// if specified, perform revocation/expiration checks
    pub validity_check: Option<CrlMode>,
    /// will fail if the leaf certificate does not declare an enforced key-usage
    pub required_leaf_cert_key_usage: Vec<EnforceKeyUsage>,
    /// OID of extensions that cannot be present outside of the leaf certificate.
    /// This is specifically used in the Android App integrity check.
    pub leaf_only_extensions: Vec<String>,
}

impl CertificateValidationOptions {
    /// No validation is performed
    pub fn no_validation() -> Self {
        Self {
            require_root_termination: false,
            integrity_check: false,
            validity_check: None,
            required_leaf_cert_key_usage: Default::default(),
            leaf_only_extensions: Default::default(),
        }
    }

    /// Full validation is performed, each certificate must be:
    /// * not expired
    /// * not revoked
    /// * correctly signed by the parent cert in the chain
    /// * part of a chain that terminates to a root CA
    /// * path length is valid
    /// * key usage is validated
    pub fn full_validation(required_leaf_cert_key_usage: Option<Vec<EnforceKeyUsage>>) -> Self {
        Self {
            require_root_termination: true,
            integrity_check: true,
            validity_check: Some(CrlMode::X509),
            required_leaf_cert_key_usage: required_leaf_cert_key_usage.unwrap_or_default(),
            leaf_only_extensions: Default::default(),
        }
    }

    /// Only signature and revocation checks are performed
    pub fn signature_and_revocation(
        required_leaf_cert_key_usage: Option<Vec<EnforceKeyUsage>>,
    ) -> Self {
        Self {
            require_root_termination: false,
            integrity_check: true,
            validity_check: Some(CrlMode::X509),
            required_leaf_cert_key_usage: required_leaf_cert_key_usage.unwrap_or_default(),
            leaf_only_extensions: Default::default(),
        }
    }
}

#[derive(Clone)]
pub struct CertificateValidatorImpl {
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    crl_cache: Arc<X509CrlCache>,
    clock: Arc<dyn Clock>,
    android_attestation_crl_cache: Arc<AndroidAttestationCrlCache>,
}

impl CertificateValidatorImpl {
    pub fn new(
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        crl_cache: Arc<X509CrlCache>,
        clock: Arc<dyn Clock>,
        android_attestation_crl_cache: Arc<AndroidAttestationCrlCache>,
    ) -> Self {
        Self {
            key_algorithm_provider,
            crl_cache,
            clock,
            android_attestation_crl_cache,
        }
    }
}

#[cfg(test)]
mod tests {
    use mockall::predicate::eq;
    use time::Duration;
    use x509_parser::pem::Pem;

    use super::*;
    use crate::provider::caching_loader::android_attestation_crl::AndroidAttestationCrlResolver;
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

        let http_client = Arc::new(mock_http_client);
        let remote_entity_storage = Arc::new(mock_remote_entity_storage);
        let validator = CertificateValidatorImpl::new(
            Arc::new(key_algorithm),
            Arc::new(X509CrlCache::new(
                Arc::new(X509CrlResolver::new(http_client.clone())),
                remote_entity_storage.clone(),
                100,
                Duration::days(1),
                Duration::days(1),
            )),
            Arc::new(DefaultClock),
            Arc::new(AndroidAttestationCrlCache::new(
                Arc::new(AndroidAttestationCrlResolver::new(http_client)),
                remote_entity_storage,
                100,
                Duration::days(1),
                Duration::days(1),
            )),
        );

        let pem = Pem::iter_from_buffer(CERTIFICATE.as_bytes())
            .next()
            .unwrap()
            .unwrap();

        // The check will fail because we do not provide a mock CRL
        let _error = validator
            .check_revocation(&pem.parse_x509().unwrap(), None, CrlMode::X509)
            .await;
    }
}

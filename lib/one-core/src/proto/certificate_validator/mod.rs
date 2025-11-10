use std::sync::Arc;

use time::Duration;

use crate::proto::clock::Clock;
use crate::provider::caching_loader::android_attestation_crl::AndroidAttestationCrlCache;
use crate::provider::caching_loader::x509_crl::X509CrlCache;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::service::certificate::dto::CertificateX509AttributesDTO;
use crate::service::error::ServiceError;

pub mod parse;
mod revocation;
mod x509_extension;

#[cfg(test)]
mod test;

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
    /// Extract leaf certificate_validator from the provided PEM chain
    /// Optionally validate the chain depending on the options
    async fn parse_pem_chain(
        &self,
        pem_chain: &str,
        validation: CertificateValidationOptions,
    ) -> Result<ParsedCertificate, ServiceError>;

    /// Validates the pem_chain starting from a leaf certificate_validator against a ca_chain starting
    /// from an intermediary or root CA.
    /// Returns the parsed certificate_validator according to the `cert_selection`.
    async fn validate_chain_against_ca_chain(
        &self,
        pem_chain: &str,
        ca_pem_chain: &str,
        validation: CertificateValidationOptions,
        cert_selection: CertSelection,
    ) -> Result<ParsedCertificate, ServiceError>;
}

pub enum CertSelection {
    /// Last certificate_validator in the CA chain
    LowestCaChain,
    /// Leaf certificate_validator of the whole chain
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
    /// will fail if the leaf certificate_validator does not declare an enforced key-usage
    pub required_leaf_cert_key_usage: Vec<EnforceKeyUsage>,
    /// OID of extensions that cannot be present outside of the leaf certificate_validator.
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

    /// Full validation is performed, each certificate_validator must be:
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
    clock_leeway: Duration,
    android_attestation_crl_cache: Arc<AndroidAttestationCrlCache>,
}

impl CertificateValidatorImpl {
    pub fn new(
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        crl_cache: Arc<X509CrlCache>,
        clock: Arc<dyn Clock>,
        clock_leeway: Duration,
        android_attestation_crl_cache: Arc<AndroidAttestationCrlCache>,
    ) -> Self {
        Self {
            key_algorithm_provider,
            crl_cache,
            clock,
            clock_leeway,
            android_attestation_crl_cache,
        }
    }
}

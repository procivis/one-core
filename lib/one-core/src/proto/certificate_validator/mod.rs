use std::collections::HashMap;
use std::sync::Arc;

use time::Duration;
use x509_parser::certificate::X509Certificate;

use crate::config::core_config::{CacheEntityCacheType, CacheEntityConfig, CoreConfig};
use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::proto::clock::{Clock, DefaultClock};
use crate::proto::http_client::HttpClient;
use crate::provider::caching_loader::android_attestation_crl::{
    AndroidAttestationCrlCache, AndroidAttestationCrlResolver,
};
use crate::provider::caching_loader::x509_crl::{X509CrlCache, X509CrlResolver};
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::remote_entity_storage::RemoteEntityStorage;
use crate::provider::remote_entity_storage::db_storage::DbStorage;
use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
use crate::repository::remote_entity_cache_repository::RemoteEntityCacheRepository;
use crate::service::certificate::dto::CertificateX509AttributesDTO;

pub mod parse;
mod revocation;
pub(crate) mod x509_extension;

#[cfg(test)]
mod test;

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("No certificates specified in the chain")]
    EmptyChain,
    #[error("Unsupported algorithm: `{0}`")]
    UnsupportedAlgorithm(String),
    #[error("CRL check failure: `{0}`")]
    CRLCheckFailed(String),
    #[error("Certificate signature invalid")]
    CertificateSignatureInvalid,
    #[error("Certificate revoked")]
    CertificateRevoked,
    #[error("Certificate is expired")]
    CertificateExpired,
    #[error("Certificate is not yet valid")]
    CertificateNotYetValid,
    #[error("CRL is not up to date")]
    CRLOutdated,
    #[error("CRL signature invalid")]
    CRLSignatureInvalid,
    #[error("Invalid CA chain: {0}")]
    InvalidCaCertificateChain(String),
    #[error("Unknown critical X.509 extension: {0}")]
    UnknownCriticalExtension(String),
    #[error("Certificate key usage violation: {0}")]
    KeyUsageViolation(String),
    #[error("Basic constraints violation: {0}")]
    BasicConstraintsViolation(String),

    #[error("PEM error: `{0}`")]
    PEMError(#[from] x509_parser::error::PEMError),
    #[expect(clippy::enum_variant_names)]
    #[error("X509 nom error: `{0}`")]
    X509NomError(#[from] x509_parser::nom::Err<x509_parser::error::X509Error>),
    #[expect(clippy::enum_variant_names)]
    #[error("X509 error: `{0}`")]
    X509ParserError(#[from] x509_parser::error::X509Error),
    #[error("Hash error: `{0}`")]
    HasherError(#[from] one_crypto::HasherError),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for Error {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::HasherError(_) => ErrorCode::BR_0000,
            Self::EmptyChain
            | Self::UnsupportedAlgorithm(_)
            | Self::PEMError(_)
            | Self::X509NomError(_)
            | Self::X509ParserError(_) => ErrorCode::BR_0224,
            Self::CRLCheckFailed(_) => ErrorCode::BR_0233,
            Self::CertificateSignatureInvalid => ErrorCode::BR_0211,
            Self::CertificateRevoked => ErrorCode::BR_0212,
            Self::CertificateExpired => ErrorCode::BR_0213,
            Self::CertificateNotYetValid => ErrorCode::BR_0359,
            Self::CRLOutdated => ErrorCode::BR_0234,
            Self::CRLSignatureInvalid => ErrorCode::BR_0235,
            Self::InvalidCaCertificateChain(_) => ErrorCode::BR_0244,
            Self::UnknownCriticalExtension(_) => ErrorCode::BR_0248,
            Self::KeyUsageViolation(_) => ErrorCode::BR_0249,
            Self::BasicConstraintsViolation(_) => ErrorCode::BR_0250,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait CertificateValidator: Send + Sync {
    /// Extract leaf certificate_validator from the provided PEM chain
    /// Optionally validate the chain depending on the options
    async fn parse_pem_chain(
        &self,
        pem_chain: &str,
        validation: CertificateValidationOptions,
    ) -> Result<ParsedCertificate, Error>;

    /// Validates the pem_chain starting from a leaf certificate_validator against a ca_chain starting
    /// from an intermediary or root CA.
    /// Returns the parsed certificate_validator according to the `cert_selection`.
    async fn validate_chain_against_ca_chain(
        &self,
        pem_chain: &str,
        ca_pem_chain: &str,
        validation: CertificateValidationOptions,
        cert_selection: CertSelection,
    ) -> Result<ParsedCertificate, Error>;
}

#[derive(Debug, Clone)]
pub struct ParsedCertificate {
    pub attributes: CertificateX509AttributesDTO,
    pub subject_common_name: Option<String>,
    pub subject_key_identifier: Option<String>,
    pub public_key: KeyHandle,
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
    KeyCertSign,
    CRLSign,
}

pub(crate) type LeafValidation = fn(&X509Certificate) -> Result<(), Error>;

pub(crate) struct CertificateValidationOptions {
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
    pub leaf_validations: Vec<LeafValidation>,
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
            leaf_validations: Default::default(),
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
            leaf_validations: Default::default(),
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
            leaf_validations: Default::default(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct CertificateValidatorImpl {
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    crl_cache: Arc<X509CrlCache>,
    clock: Arc<dyn Clock>,
    clock_leeway: Duration,
    android_attestation_crl_cache: Arc<AndroidAttestationCrlCache>,
}

impl CertificateValidatorImpl {
    pub(crate) fn new(
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

pub(crate) fn certificate_validator_from_config(
    config: &CoreConfig,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    client: Arc<dyn HttpClient>,
    remote_entity_cache_repository: Arc<dyn RemoteEntityCacheRepository>,
) -> Arc<dyn CertificateValidator> {
    Arc::new(CertificateValidatorImpl::new(
        key_algorithm_provider.clone(),
        Arc::new(initialize_x509_crl_cache(
            config,
            remote_entity_cache_repository,
        )),
        Arc::new(DefaultClock),
        config.certificate_validation.leeway,
        Arc::new(initialize_android_key_attestation_crl_cache(client)),
    ))
}

fn initialize_android_key_attestation_crl_cache(
    client: Arc<dyn HttpClient>,
) -> AndroidAttestationCrlCache {
    AndroidAttestationCrlCache::new(
        Arc::new(AndroidAttestationCrlResolver::new(client)),
        Arc::new(InMemoryStorage::new(HashMap::new())),
        1,
        Duration::days(1),
        Duration::days(1),
    )
}

fn initialize_x509_crl_cache(
    config: &CoreConfig,
    remote_entity_cache_repository: Arc<dyn RemoteEntityCacheRepository>,
) -> X509CrlCache {
    let config = config
        .cache_entities
        .entities
        .get("X509_CRL")
        .cloned()
        .unwrap_or(CacheEntityConfig {
            cache_refresh_timeout: Duration::days(1),
            cache_size: 100,
            cache_type: CacheEntityCacheType::Db,
            refresh_after: Duration::minutes(5),
        });

    let storage: Arc<dyn RemoteEntityStorage> = match config.cache_type {
        CacheEntityCacheType::Db => Arc::new(DbStorage::new(remote_entity_cache_repository)),
        CacheEntityCacheType::InMemory => Arc::new(InMemoryStorage::new(HashMap::new())),
    };

    X509CrlCache::new(
        Arc::new(X509CrlResolver::new(Default::default())),
        storage,
        config.cache_size as usize,
        config.cache_refresh_timeout,
        config.refresh_after,
    )
}

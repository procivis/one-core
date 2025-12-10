use std::collections::HashMap;
use std::sync::Arc;

use time::Duration;

use crate::config::core_config::{CacheEntityCacheType, CacheEntityConfig, CoreConfig};
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

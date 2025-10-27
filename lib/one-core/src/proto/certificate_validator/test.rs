use std::collections::HashMap;
use std::sync::Arc;

use mockall::predicate::eq;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose,
};
use time::{Duration, OffsetDateTime};
use x509_parser::pem::Pem;

use crate::config::core_config::KeyAlgorithmType;
use crate::proto::certificate_validator::{
    CertSelection, CertificateValidationOptions, CertificateValidator, CertificateValidatorImpl,
    CrlMode,
};
use crate::proto::clock::DefaultClock;
use crate::proto::http_client::reqwest_client::ReqwestClient;
use crate::proto::http_client::{
    Method, MockHttpClient, Request, RequestBuilder, Response, StatusCode,
};
use crate::provider::caching_loader::android_attestation_crl::{
    AndroidAttestationCrlCache, AndroidAttestationCrlResolver,
};
use crate::provider::caching_loader::x509_crl::{X509CrlCache, X509CrlResolver};
use crate::provider::key_algorithm::KeyAlgorithm;
use crate::provider::key_algorithm::provider::{
    KeyAlgorithmProviderImpl, MockKeyAlgorithmProvider,
};
use crate::provider::remote_entity_storage::MockRemoteEntityStorage;
use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
use crate::service::error::{ServiceError, ValidationError};

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

fn create_ca_cert(path_len_constraint: Option<u8>) -> (Certificate, KeyPair) {
    let mut params = CertificateParams::default();
    params.is_ca = match path_len_constraint {
        Some(value) => IsCa::Ca(BasicConstraints::Constrained(value)),
        None => IsCa::Ca(BasicConstraints::Unconstrained),
    };

    params.use_authority_key_identifier_extension = true;
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "CA cert");
    params.distinguished_name = distinguished_name;

    params.not_before = OffsetDateTime::now_utc()
        .checked_sub(Duration::weeks(100))
        .unwrap(); // ~2year before now
    params.not_after = OffsetDateTime::now_utc()
        .checked_add(Duration::weeks(500))
        .unwrap(); // ~10years from now

    let keys = KeyPair::generate().unwrap();
    let cert = params.self_signed(&keys).unwrap();
    (cert, keys)
}

fn create_cert(
    mut params: CertificateParams,
    issuer: &Certificate,
    issuer_keys: &KeyPair,
) -> (Certificate, KeyPair) {
    if params.key_usages.is_empty() {
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    }

    if params.distinguished_name.iter().next().is_none() {
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, "test cert");
        params.distinguished_name = distinguished_name;
    }

    let parent_not_before = issuer.params().not_before;
    let parent_not_after = issuer.params().not_after;
    if params.not_before < parent_not_before {
        params.not_before = parent_not_before;
    }
    if params.not_after > parent_not_after {
        params.not_after = parent_not_after;
    }

    let keys = KeyPair::generate().unwrap();
    let cert = params.signed_by(&keys, issuer, issuer_keys).unwrap();
    (cert, keys)
}

fn create_intermediate_ca_cert(
    path_len_constraint: Option<u8>,
    issuer: &Certificate,
    issuer_keys: &KeyPair,
) -> (Certificate, KeyPair) {
    let mut params = CertificateParams::default();
    params.is_ca = match path_len_constraint {
        Some(value) => IsCa::Ca(BasicConstraints::Constrained(value)),
        None => IsCa::Ca(BasicConstraints::Unconstrained),
    };

    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "Intermediate CA");
    params.distinguished_name = distinguished_name;

    create_cert(params, issuer, issuer_keys)
}

fn create_certificate_validator() -> CertificateValidatorImpl {
    let key_algorithm_provider = Arc::new(KeyAlgorithmProviderImpl::new(HashMap::from_iter(vec![
        (
            KeyAlgorithmType::Eddsa,
            Arc::new(crate::provider::key_algorithm::eddsa::Eddsa) as Arc<dyn KeyAlgorithm>,
        ),
        (
            KeyAlgorithmType::Ecdsa,
            Arc::new(crate::provider::key_algorithm::ecdsa::Ecdsa) as Arc<dyn KeyAlgorithm>,
        ),
    ])));
    let crl_cache = Arc::new(X509CrlCache::new(
        Arc::new(X509CrlResolver::new(Arc::new(ReqwestClient::default()))),
        Arc::new(InMemoryStorage::new(HashMap::new())),
        100,
        Duration::minutes(1),
        Duration::minutes(1),
    ));
    let android_key_attestation_crl_cache = Arc::new(AndroidAttestationCrlCache::new(
        Arc::new(AndroidAttestationCrlResolver::new(Arc::new(
            ReqwestClient::default(),
        ))),
        Arc::new(InMemoryStorage::new(HashMap::new())),
        1,
        Duration::days(1),
        Duration::days(1),
    ));

    CertificateValidatorImpl::new(
        key_algorithm_provider,
        crl_cache,
        Arc::new(DefaultClock),
        android_key_attestation_crl_cache,
    )
}

#[tokio::test]
async fn validate_chain_fails_on_violation_of_root_ca_path_len_constraint() {
    let (ca_cert, ca_key) = create_ca_cert(Some(0));

    let (intermediate_cert, intermediate_key) =
        create_intermediate_ca_cert(None, &ca_cert, &ca_key);

    let (leaf_cert, _leaf_key) = create_cert(
        CertificateParams::default(),
        &intermediate_cert,
        &intermediate_key,
    );

    let validator = create_certificate_validator();
    let result = validator
        .validate_chain_against_ca_chain(
            &format!("{}{}", leaf_cert.pem(), &intermediate_cert.pem()),
            &ca_cert.pem(),
            CertificateValidationOptions::full_validation(None),
            CertSelection::Leaf,
        )
        .await;
    match result {
        Err(ServiceError::Validation(ValidationError::BasicConstraintsViolation(_))) => { /* ok */ }
        Err(other) => panic!(
            "Got Err({other}), expected Err(ServiceError::Validation(ValidationError::BasicConstraintsViolation)",
        ),
        Ok(_) => panic!(
            "Got Ok(_), expected Err(ServiceError::Validation(ValidationError::BasicConstraintsViolation)"
        ),
    }
}

#[tokio::test]
async fn validate_chain_fails_on_violation_of_intermediate_ca_path_len_constraint() {
    let (ca_cert, ca_key) = create_ca_cert(None);

    let (first_intermediate_cert, first_intermediate_key) =
        create_intermediate_ca_cert(Some(0), &ca_cert, &ca_key);

    let (second_intermediate_cert, second_intermediate_key) =
        create_intermediate_ca_cert(None, &first_intermediate_cert, &first_intermediate_key);

    let (leaf_cert, _leaf_key) = create_cert(
        CertificateParams::default(),
        &second_intermediate_cert,
        &second_intermediate_key,
    );

    let validator = create_certificate_validator();
    let result = validator
        .validate_chain_against_ca_chain(
            &format!(
                "{}{}{}",
                leaf_cert.pem(),
                second_intermediate_cert.pem(),
                first_intermediate_cert.pem()
            ),
            &ca_cert.pem(),
            CertificateValidationOptions::full_validation(None),
            CertSelection::Leaf,
        )
        .await;
    match result {
        Err(ServiceError::Validation(ValidationError::BasicConstraintsViolation(_))) => { /* ok */ }
        Err(other) => panic!(
            "Got Err({other}), expected Err(ServiceError::Validation(ValidationError::BasicConstraintsViolation)",
        ),
        Ok(_) => panic!(
            "Got Ok(_), expected Err(ServiceError::Validation(ValidationError::BasicConstraintsViolation)"
        ),
    }
}

#[tokio::test]
async fn validate_chain_succeeds_when_path_len_constraints_are_satisfied() {
    let (ca_cert, ca_key) = create_ca_cert(Some(2));

    let (first_intermediate_cert, first_intermediate_key) =
        create_intermediate_ca_cert(Some(1), &ca_cert, &ca_key);

    let (second_intermediate_cert, second_intermediate_key) =
        create_intermediate_ca_cert(None, &first_intermediate_cert, &first_intermediate_key);

    let (leaf_cert, _leaf_key) = create_cert(
        CertificateParams::default(),
        &second_intermediate_cert,
        &second_intermediate_key,
    );

    let validator = create_certificate_validator();
    validator
        .validate_chain_against_ca_chain(
            &format!(
                "{}{}{}",
                leaf_cert.pem(),
                second_intermediate_cert.pem(),
                first_intermediate_cert.pem()
            ),
            &ca_cert.pem(),
            CertificateValidationOptions::full_validation(None),
            CertSelection::Leaf,
        )
        .await
        .unwrap();
}

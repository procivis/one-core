use std::sync::Arc;

use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use serde_json::json;
use similar_asserts::assert_eq;
use standardized_types::csc::{CredentialCertificate, CredentialInfoResponse, CredentialKey};
use time::OffsetDateTime;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use x509_parser::pem::parse_x509_pem;

use super::Sign8KeyProvider;
use crate::config::core_config::KeyAlgorithmType;
use crate::model::key::Key;
use crate::proto::certificate_validator::{MockCertificateValidator, ParsedCertificate};
use crate::proto::csc::model::CredentialToken;
use crate::proto::csc::{CscClientError, MockCscClient};
use crate::proto::http_client::reqwest_client::ReqwestClient;
use crate::provider::key_algorithm::KeyAlgorithm;
use crate::provider::key_algorithm::ecdsa::Ecdsa;
use crate::provider::key_storage::KeyStorage;
use crate::provider::key_storage::error::KeyStorageError;
use crate::service::certificate::dto::CertificateX509AttributesDTO;
use crate::service::test_utilities::dummy_organisation;

const PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgBtS6wnGJbBwe77ja
WaJCk/hdfWVs/BULcYqdsxcI+hChRANCAATar90dNM4yUrcJUWo4TAoX7Bw/W+NM
Oy/u5r2GTZy1eCR2c6+t8oh43EPQs10bOfWpioVzJn2GD4vqRieKqhT7
-----END PRIVATE KEY-----";

const CERTIFICATE_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBgDCCASWgAwIBAgIUTegJQnZHJRU4OBaFx9D7NgK54QUwCgYIKoZIzj0EAwIw
FTETMBEGA1UEAwwKc2lnbjgtdGVzdDAeFw0yNjA2MjMxNDA4NDRaFw0zNjA2MjAx
NDA4NDRaMBUxEzARBgNVBAMMCnNpZ244LXRlc3QwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAATar90dNM4yUrcJUWo4TAoX7Bw/W+NMOy/u5r2GTZy1eCR2c6+t8oh4
3EPQs10bOfWpioVzJn2GD4vqRieKqhT7o1MwUTAdBgNVHQ4EFgQU8uAPNYbwCQfg
039hKwKBKi0v0FMwHwYDVR0jBBgwFoAU8uAPNYbwCQfg039hKwKBKi0v0FMwDwYD
VR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEAjcokw0KxbBANknottH8m
u/ffY2XivToQacDwgB/w2wUCIQCfMnvo0SzybSjQ0w8bilFIVVyiYgYzcjb+ZTCF
TbopFw==
-----END CERTIFICATE-----";

const CERTIFICATE_B64: &str = "MIIBgDCCASWgAwIBAgIUTegJQnZHJRU4OBaFx9D7NgK54QUwCgYIKoZIzj0EAwIwFTETMBEGA1UEAwwKc2lnbjgtdGVzdDAeFw0yNjA2MjMxNDA4NDRaFw0zNjA2MjAxNDA4NDRaMBUxEzARBgNVBAMMCnNpZ244LXRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATar90dNM4yUrcJUWo4TAoX7Bw/W+NMOy/u5r2GTZy1eCR2c6+t8oh43EPQs10bOfWpioVzJn2GD4vqRieKqhT7o1MwUTAdBgNVHQ4EFgQU8uAPNYbwCQfg039hKwKBKi0v0FMwHwYDVR0jBBgwFoAU8uAPNYbwCQfg039hKwKBKi0v0FMwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEAjcokw0KxbBANknottH8mu/ffY2XivToQacDwgB/w2wUCIQCfMnvo0SzybSjQ0w8bilFIVVyiYgYzcjb+ZTCFTbopFw==";

const CREDENTIAL_ID: &str = "credential-123";

fn params(url: &str) -> serde_json::Value {
    json!({
        "cscBaseUrl": url,
        "oauthUrl": url,
        "redirectUrl": "http://redirect.test/callback",
        "accountId": "account-id",
        "certificate": CERTIFICATE_PEM,
        "clientId": "client-id",
        "clientSecret": "client-secret",
        "privateKey": PRIVATE_KEY_PEM,
    })
}

fn parsed_certificate() -> ParsedCertificate {
    let (_, pem) = parse_x509_pem(CERTIFICATE_PEM.as_bytes()).unwrap();
    let cert = pem.parse_x509().unwrap();
    let public_key = Ecdsa
        .parse_der(cert.tbs_certificate.subject_pki.raw)
        .unwrap();
    let now = OffsetDateTime::now_utc();
    ParsedCertificate {
        attributes: CertificateX509AttributesDTO {
            serial_number: "test".to_string(),
            not_before: now,
            not_after: now,
            issuer: "sign8-test".to_string(),
            subject: "sign8-test".to_string(),
            fingerprint: "test".to_string(),
            extensions: vec![],
        },
        subject_common_name: Some("sign8-test".to_string()),
        subject_key_identifier: None,
        public_key,
    }
}

async fn mount_authorize_tls(mock_server: &MockServer, code: &str, expect: u64) {
    let code = code.to_string();
    Mock::given(method(Method::POST))
        .and(path("/oauth2/authorize_tls"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .and(body_string_contains(format!(
            "credentialID={CREDENTIAL_ID}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "code": code })))
        .expect(expect)
        .mount(mock_server)
        .await;
}

#[tokio::test]
async fn test_generate_success() {
    let mock_server = MockServer::start().await;
    mount_authorize_tls(&mock_server, "auth-code", 1).await;

    let mut csc_client = MockCscClient::new();
    csc_client.expect_exchange_code().times(1).returning(|_| {
        Ok(CredentialToken {
            access_token: "access-token".to_string(),
            credential_id: CREDENTIAL_ID.to_string(),
        })
    });
    csc_client
        .expect_credential_info()
        .times(1)
        .returning(|_, _, _| {
            Ok(CredentialInfoResponse {
                key: CredentialKey { algo: vec![] },
                cert: Some(CredentialCertificate {
                    certificates: vec![CERTIFICATE_B64.to_string()],
                }),
            })
        });
    csc_client
        .expect_revoke_access_token()
        .times(1)
        .returning(|_, _, _, _| {});

    let mut certificate_validator = MockCertificateValidator::new();
    certificate_validator
        .expect_parse_pem_chain()
        .times(1)
        .returning(|_, _| Ok(parsed_certificate()));

    let provider = Sign8KeyProvider::new(
        "SIGN8".to_string(),
        Arc::new(csc_client),
        Arc::new(ReqwestClient::default()),
        Arc::new(certificate_validator),
        params(&mock_server.uri()),
    )
    .unwrap();

    let generated = provider
        .generate(
            Uuid::new_v4().into(),
            KeyAlgorithmType::Ecdsa,
            json!({ "credentialId": CREDENTIAL_ID }),
        )
        .await
        .unwrap();

    assert_eq!(
        parsed_certificate().public_key.public_key_as_raw(),
        generated.public_key
    );
    assert_eq!(
        Some(CREDENTIAL_ID.as_bytes().to_vec()),
        generated.key_reference
    );
}

#[tokio::test]
async fn test_generate_fails_on_invalid_params() {
    let provider = Sign8KeyProvider::new(
        "SIGN8".to_string(),
        Arc::new(MockCscClient::new()),
        Arc::new(ReqwestClient::default()),
        Arc::new(MockCertificateValidator::new()),
        params("http://test.com"),
    )
    .unwrap();

    // Missing the required `credentialId` field.
    let result = provider
        .generate(Uuid::new_v4().into(), KeyAlgorithmType::Ecdsa, json!({}))
        .await;

    assert!(matches!(result, Err(KeyStorageError::InvalidParams(_))));
}

fn test_key(key_reference: Option<Vec<u8>>) -> Key {
    let now = OffsetDateTime::now_utc();
    Key {
        autogenerated: false,
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        public_key: parsed_certificate().public_key.public_key_as_raw(),
        name: "sign8-key".to_string(),
        key_reference,
        storage_type: "SIGN8".to_string(),
        key_type: "ECDSA".to_string(),
        organisation: dummy_organisation(None).into(),
    }
}

fn provider(
    url: &str,
    csc_client: MockCscClient,
    certificate_validator: MockCertificateValidator,
) -> Sign8KeyProvider {
    Sign8KeyProvider::new(
        "SIGN8".to_string(),
        Arc::new(csc_client),
        Arc::new(ReqwestClient::default()),
        Arc::new(certificate_validator),
        params(url),
    )
    .unwrap()
}

#[test]
fn test_key_handle_success() {
    let provider = provider(
        "http://test.com",
        MockCscClient::new(),
        MockCertificateValidator::new(),
    );

    let key_handle = provider
        .key_handle(&test_key(Some(CREDENTIAL_ID.as_bytes().to_vec())))
        .unwrap();

    let signature = key_handle.signature().unwrap();
    assert!(signature.private().is_some());
    assert_eq!(
        parsed_certificate().public_key.public_key_as_raw(),
        key_handle.public_key_as_raw()
    );
}

const MESSAGE: &[u8] = b"message-to-sign";
const SIGNATURE: &[u8] = b"the-signature";

#[tokio::test]
async fn test_sign_success() {
    let mock_server = MockServer::start().await;
    mount_authorize_tls(&mock_server, "auth-code", 1).await;

    let expected_hash = SHA256.hash(MESSAGE).unwrap();

    let mut csc_client = MockCscClient::new();
    csc_client.expect_exchange_code().times(1).returning(|_| {
        Ok(CredentialToken {
            access_token: "access-token".to_string(),
            credential_id: CREDENTIAL_ID.to_string(),
        })
    });
    csc_client
        .expect_sign_hash()
        .times(1)
        .withf(move |request| {
            request.credential_id == CREDENTIAL_ID
                && request.access_token == "access-token"
                && request.hashes == [expected_hash.as_slice()]
        })
        .returning(|_| Ok(vec![SIGNATURE.to_vec()]));
    csc_client
        .expect_revoke_access_token()
        .times(1)
        .returning(|_, _, _, _| {});

    let provider = provider(
        &mock_server.uri(),
        csc_client,
        MockCertificateValidator::new(),
    );

    let key_handle = provider
        .key_handle(&test_key(Some(CREDENTIAL_ID.as_bytes().to_vec())))
        .unwrap();

    let signature = key_handle.sign(MESSAGE).await.unwrap();

    assert_eq!(SIGNATURE, signature);
}

#[tokio::test]
async fn test_sign_revokes_access_token_on_signing_failure() {
    let mock_server = MockServer::start().await;
    mount_authorize_tls(&mock_server, "auth-code", 1).await;

    let mut csc_client = MockCscClient::new();
    csc_client.expect_exchange_code().times(1).returning(|_| {
        Ok(CredentialToken {
            access_token: "access-token".to_string(),
            credential_id: CREDENTIAL_ID.to_string(),
        })
    });
    csc_client
        .expect_sign_hash()
        .times(1)
        .returning(|_| Err(CscClientError::EmptySignedDocuments));
    // The access token must still be revoked even when signing fails.
    csc_client
        .expect_revoke_access_token()
        .times(1)
        .returning(|_, _, _, _| {});

    let provider = provider(
        &mock_server.uri(),
        csc_client,
        MockCertificateValidator::new(),
    );

    let key_handle = provider
        .key_handle(&test_key(Some(CREDENTIAL_ID.as_bytes().to_vec())))
        .unwrap();

    let result = key_handle.sign(MESSAGE).await;

    assert!(result.is_err());
}

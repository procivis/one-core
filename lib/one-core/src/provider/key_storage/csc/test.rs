use std::collections::HashMap;
use std::sync::Arc;

use ct_codecs::{Base64, Base64UrlSafeNoPadding, Decoder, Encoder};
use one_crypto::hasher::sha256::SHA256;
use one_crypto::signer::rsa::RsaSigner;
use one_crypto::{Hasher, Signer};
use serde_json::json;
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use x509_parser::pem::parse_x509_pem;

use super::CscKeyProvider;
use crate::config::core_config::KeyAlgorithmType;
use crate::model::key::Key;
use crate::proto::certificate_validator::{MockCertificateValidator, ParsedCertificate};
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

fn sign8_params(url: &str) -> serde_json::Value {
    json!({
        "auth": "SIGN8_TLS",
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

async fn mount_sign8_authorization(mock_server: &MockServer) {
    Mock::given(method(Method::POST))
        .and(path("/oauth2/authorize_tls"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .and(body_string_contains(format!(
            "credentialID={CREDENTIAL_ID}"
        )))
        .and(body_string_contains("code_challenge_method=S256"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "code": "auth-code" })))
        .expect(1)
        .mount(mock_server)
        .await;
    Mock::given(method(Method::POST))
        .and(path("/oauth2/token"))
        .and(body_string_contains("code=auth-code"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "access-token",
            "credentialID": CREDENTIAL_ID,
        })))
        .expect(1)
        .mount(mock_server)
        .await;
    Mock::given(method(Method::POST))
        .and(path("/oauth2/revoke"))
        .and(body_string_contains("token=access-token"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(mock_server)
        .await;
}

fn sign8_provider(url: &str, certificate_validator: MockCertificateValidator) -> CscKeyProvider {
    CscKeyProvider::new(
        "SIGN8".to_string(),
        Arc::new(ReqwestClient::default()),
        Arc::new(certificate_validator),
        sign8_params(url),
    )
    .unwrap()
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

const MESSAGE: &[u8] = b"message-to-sign";
const SIGNATURE_R: [u8; 32] = [1; 32];
const SIGNATURE_S: [u8; 32] = [2; 32];

fn der_signature() -> Vec<u8> {
    [
        &[0x30, 68, 0x02, 32],
        &SIGNATURE_R[..],
        &[0x02, 32],
        &SIGNATURE_S[..],
    ]
    .concat()
}

#[tokio::test]
async fn test_generate_success() {
    let mock_server = MockServer::start().await;
    mount_sign8_authorization(&mock_server).await;
    Mock::given(method(Method::POST))
        .and(path("/csc/v2/credentials/info"))
        .and(header("authorization", "Bearer access-token"))
        .and(body_string_contains(CREDENTIAL_ID))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "key": { "status": "enabled", "algo": ["1.2.840.10045.4.3.2"] },
            "cert": { "certificates": [CERTIFICATE_B64] },
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut certificate_validator = MockCertificateValidator::new();
    certificate_validator
        .expect_parse_pem_chain()
        .times(1)
        .returning(|_, _| Ok(parsed_certificate()));

    let generated = sign8_provider(&mock_server.uri(), certificate_validator)
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
    let provider = sign8_provider("http://test.com", MockCertificateValidator::new());

    let result = provider
        .generate(Uuid::new_v4().into(), KeyAlgorithmType::Ecdsa, json!({}))
        .await;

    assert!(matches!(result, Err(KeyStorageError::InvalidParams(_))));
}

#[test]
fn test_key_handle_success() {
    let provider = sign8_provider("http://test.com", MockCertificateValidator::new());

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

#[tokio::test]
async fn test_sign_success() {
    let mock_server = MockServer::start().await;
    mount_sign8_authorization(&mock_server).await;
    let expected_hash = Base64::encode_to_string(SHA256.hash(MESSAGE).unwrap()).unwrap();
    Mock::given(method(Method::POST))
        .and(path("/csc/v2/signatures/signHash"))
        .and(header("authorization", "Bearer access-token"))
        .and(body_string_contains(CREDENTIAL_ID))
        .and(body_string_contains(expected_hash))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "signatures": [Base64::encode_to_string(der_signature()).unwrap()],
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let key_handle = sign8_provider(&mock_server.uri(), MockCertificateValidator::new())
        .key_handle(&test_key(Some(CREDENTIAL_ID.as_bytes().to_vec())))
        .unwrap();

    let signature = key_handle.sign(MESSAGE).await.unwrap();

    assert_eq!([SIGNATURE_R, SIGNATURE_S].concat(), signature);
}

#[tokio::test]
async fn test_sign_revokes_access_token_on_signing_failure() {
    let mock_server = MockServer::start().await;
    mount_sign8_authorization(&mock_server).await;
    Mock::given(method(Method::POST))
        .and(path("/csc/v2/signatures/signHash"))
        .respond_with(ResponseTemplate::new(500))
        .expect(1)
        .mount(&mock_server)
        .await;

    let key_handle = sign8_provider(&mock_server.uri(), MockCertificateValidator::new())
        .key_handle(&test_key(Some(CREDENTIAL_ID.as_bytes().to_vec())))
        .unwrap();

    let result = key_handle.sign(MESSAGE).await;

    assert!(result.is_err());
}

const RSA_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCs9TRIAE2u1ips
JLF5M3yrHYUa0ig9/uGe6OGNuEBsENYqB22g02JYlJrgtKU0dU9dHQtpWSp9Z+Gj
HjgBjQrPUViYTkvob/EYCYkj1vYavqZccUBbh4vGDGxvxcfWGGggjLs5ShGvSSel
xKLu3ZDdCQieKKS6+ybZ51DEi4xfFeLEIkdSARQ8xd8zmf/5KpsawuiV8erD68P3
jLEMTF0UWtX39hOzijXuwiHfmeZyqKz3jR0h3pnVdhIfTwbpwcYTXxMTLmwpNgI5
T4fGEDoEnTL+enSGcuc1qE5ytaj2oOodeyQMyyv7yVWBvR3ArTR2q3AJFxtJzETs
p1bgvTedAgMBAAECggEAGe3UvaqV+s0OpRHHLXVjjj+pscCp2cl5R5qAHf/uYIUR
plFgxQiLqN32bhOG5NtlX384M73zWcOWFx8zpD/hy/zU/FhYlusZSNI9JgtW7+F/
DULJNC+Y68L3Craq49Ta325ZrxgEmLOt5vMYvhinXAu7qAJN195JD8fW2vBUxfhB
1FOWadYafxB591sLqMLZUM8O5qnuxD0JawnKkce3s65rOZdQH09FZNK9s23FOoEi
M9SauZlE7Z5gCNkNkbjC46HSaeb8vxNTH/aaDrRonhZhWL2JM2YRC83M4bZAMsNP
agE6+vFMIIqm5l3FC2pXcO8152BxfJcZnQwa+FUN3QKBgQDb/GsalHs3852j7q9w
5orlYuFqUyr1mFyA/KBhwwmjgwlzj6lPGI6E0hv3eqJ+aV6Z5ah+HTOH6Y1ZYaR9
ovAyi6k/EijpwZI1xWSuxqPjjQOCqI+bcHA2pkm/EIaC7rGnCJr6u9QO88pjSRu1
4fe+SRkdDz+eq1VN6jQQBK6PuwKBgQDJRdd3A873A8v+GBmC6N5zXNTdFfcZEiJU
njyL2ffT0lm5idHlPMEm2z68Wwbd1AWAtuJxrPAayJG60c4eKpdnRt1NP+kDaAdh
HudhtJq1gahzhI+F+Bdd1e7XGjAkGj0c2WYq7V9B4Orsdl2fmU/LgRBjHYeGSO8G
iPwR+wmEhwKBgEPYUV/dMzNKWu/YCRuUvnmISWT1SWZ9Gupc/0mnUS2wmBWf1OOj
+zBTbHSiycKa1KY6AgEDGIVuLj3Gs2hb/CBamlPtUdjl7iXPPwH4GUtwjgiZ29Bg
mPsBxfS7MADphLizGrkBfKEv5tdAEN/DVRjGiow/y6svxBtHg8784qlJAoGBAILH
Law4PkdEIUz1rcXgt4Gv5OPOfOK+ZK4kruST+TKaMBCdW1Oe+UXdGVNbtgd21yh+
LH5+RviwL/h6kHoLZJsHcY3bI/VBp+HUKbXTmt6q46BDltoOjGg9NFZxvqwGnITd
QURNPiLZGOwSMN0dybpKHzK3ojJ/u0e8xESOn+2LAoGAAOKZQ44E8Rod5/GAGIWN
zoTVGCRxfPsHcxcNJ0RjPBfshTz/vARJEzzM+RbWIIsOQP399E0pk1EmBR4qM2yN
0JPktkSpXU1LioD4zJh1I6r5beWLyxzvN/MCERyrw1d1nhZc4Zf/sBZGb0PmMmqz
2TwMyNLQrWKHP9e5ft1SUYk=
-----END PRIVATE KEY-----";

const RSA_CERTIFICATE_PEM: &str = "-----BEGIN CERTIFICATE-----
MIICuTCCAaGgAwIBAgIJALrxBOJYJ/RLMA0GCSqGSIb3DQEBCwUAMBMxETAPBgNV
BAMMCGR2di10ZXN0MB4XDTI2MTAxMzA2NTMxN1oXDTM2MTAxMDA2NTMxN1owEzER
MA8GA1UEAwwIZHZ2LXRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQCs9TRIAE2u1ipsJLF5M3yrHYUa0ig9/uGe6OGNuEBsENYqB22g02JYlJrgtKU0
dU9dHQtpWSp9Z+GjHjgBjQrPUViYTkvob/EYCYkj1vYavqZccUBbh4vGDGxvxcfW
GGggjLs5ShGvSSelxKLu3ZDdCQieKKS6+ybZ51DEi4xfFeLEIkdSARQ8xd8zmf/5
KpsawuiV8erD68P3jLEMTF0UWtX39hOzijXuwiHfmeZyqKz3jR0h3pnVdhIfTwbp
wcYTXxMTLmwpNgI5T4fGEDoEnTL+enSGcuc1qE5ytaj2oOodeyQMyyv7yVWBvR3A
rTR2q3AJFxtJzETsp1bgvTedAgMBAAGjEDAOMAwGA1UdEwQFMAMBAf8wDQYJKoZI
hvcNAQELBQADggEBACvX2PDMn7j1gvX7asvJXmJOYIct3uxWVTl/OgWWfW5T7J9Y
bYyO97D/QJnYdmnMFQzpysGGXqz/hDCKzo+aRZEFHPcAM1v6vLiFc5Q48GwV9x8E
+vIHOL8+hHTQIPyyrek77RH6ULB0ccitetH29nrc4k5/65+kRU/hF4jXJuGJDHzz
Vuas/RjAY+rBbIUaaXh6SbZbHytSSpD5zZ8zjaRjRDMnLIfVW3acmyrZG6EWxtms
qxhQBtIDwTOfRMEhQmJXFaKcT3dhWqSj7MvdS/pYEYSknlI5pA2jAbXXz7S0y1I/
g2shjXObSodZTbd/00Lo4aaOttXBbi8Vx1n02A0=
-----END CERTIFICATE-----";

const SIGNER_CLIENT_ID: &str = "org-sealer";

fn dvv_params(url: &str) -> serde_json::Value {
    json!({
        "auth": "OAUTH2_CLIENT",
        "cscBaseUrl": url,
        "signHashBaseUrl": format!("{url}/signer"),
        "tokenUrl": format!("{url}/token"),
        "clientId": "org-da",
        "signerClientId": SIGNER_CLIENT_ID,
        "certificate": RSA_CERTIFICATE_PEM,
        "privateKey": RSA_PRIVATE_KEY_PEM,
    })
}

fn dvv_provider(url: &str, certificate_validator: MockCertificateValidator) -> CscKeyProvider {
    CscKeyProvider::new(
        "DVV".to_string(),
        Arc::new(ReqwestClient::default()),
        Arc::new(certificate_validator),
        dvv_params(url),
    )
    .unwrap()
}

async fn mount_dvv_token(mock_server: &MockServer, scope: &str) {
    Mock::given(method(Method::POST))
        .and(path("/token"))
        .and(body_string_contains("grant_type=client_credentials"))
        .and(body_string_contains(format!("scope={scope}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "dvv-token",
            "token_type": "Bearer",
            "expires_in": 300,
        })))
        .expect(1)
        .mount(mock_server)
        .await;
}

#[tokio::test]
async fn test_dvv_generate_lists_credentials() {
    let mock_server = MockServer::start().await;
    mount_dvv_token(&mock_server, "service").await;
    Mock::given(method(Method::POST))
        .and(path("/csc/v2/credentials/list"))
        .and(header("authorization", "Bearer dvv-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "credentialIDs": [CREDENTIAL_ID],
            "credentialInfos": [{
                "credentialID": CREDENTIAL_ID,
                "key": { "status": "enabled", "algo": ["1.2.840.10045.4.3.2"] },
                "cert": { "certificates": [CERTIFICATE_B64] },
            }],
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut certificate_validator = MockCertificateValidator::new();
    certificate_validator
        .expect_parse_pem_chain()
        .times(1)
        .returning(|_, _| Ok(parsed_certificate()));

    let generated = dvv_provider(&mock_server.uri(), certificate_validator)
        .generate(Uuid::new_v4().into(), KeyAlgorithmType::Ecdsa, json!({}))
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
async fn test_dvv_generate_fails_on_ambiguous_credential_list() {
    let mock_server = MockServer::start().await;
    mount_dvv_token(&mock_server, "service").await;
    let credential = |credential_id: &str| {
        json!({
            "credentialID": credential_id,
            "key": { "status": "enabled", "algo": ["1.2.840.10045.4.3.2"] },
            "cert": { "certificates": [CERTIFICATE_B64] },
        })
    };
    Mock::given(method(Method::POST))
        .and(path("/csc/v2/credentials/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "credentialIDs": ["credential-1", "credential-2"],
            "credentialInfos": [credential("credential-1"), credential("credential-2")],
        })))
        .expect(1)
        .mount(&mock_server)
        .await;
    Mock::given(method(Method::POST))
        .and(path("/csc/v2/credentials/info"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&mock_server)
        .await;

    let result = dvv_provider(&mock_server.uri(), MockCertificateValidator::new())
        .generate(Uuid::new_v4().into(), KeyAlgorithmType::Ecdsa, json!({}))
        .await;

    assert!(matches!(result, Err(KeyStorageError::Failed(_))));
}

#[tokio::test]
async fn test_dvv_sign_binds_access_token_to_hash() {
    let mock_server = MockServer::start().await;
    mount_dvv_token(&mock_server, "credential").await;
    Mock::given(method(Method::POST))
        .and(path("/signer/csc/v2/signatures/signHash"))
        .and(header("authorization", "Bearer dvv-token"))
        .and(body_string_contains(CREDENTIAL_ID))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "signatures": [Base64::encode_to_string(der_signature()).unwrap()],
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let key_handle = dvv_provider(&mock_server.uri(), MockCertificateValidator::new())
        .key_handle(&test_key(Some(CREDENTIAL_ID.as_bytes().to_vec())))
        .unwrap();

    let signature = key_handle.sign(MESSAGE).await.unwrap();

    assert_eq!([SIGNATURE_R, SIGNATURE_S].concat(), signature);

    let token_request = mock_server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .find(|request| request.url.path() == "/token")
        .unwrap();
    let form: HashMap<String, String> = serde_urlencoded::from_bytes(&token_request.body).unwrap();
    assert_eq!(form["client_id"], SIGNER_CLIENT_ID);
    assert_eq!(
        form["client_assertion_type"],
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    );

    let authorization_details: serde_json::Value =
        serde_json::from_str(&form["authorization_details"]).unwrap();
    let expected_hash = Base64::encode_to_string(SHA256.hash(MESSAGE).unwrap()).unwrap();
    assert_eq!(
        authorization_details,
        json!([{
            "type": "credential",
            "credentialID": CREDENTIAL_ID,
            "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1",
            "documentDigests": [{ "hash": expected_hash, "label": "document" }],
        }])
    );

    let (signed, signature) = form["client_assertion"].rsplit_once('.').unwrap();
    let (_, pem) = parse_x509_pem(RSA_CERTIFICATE_PEM.as_bytes()).unwrap();
    let certificate = pem.parse_x509().unwrap();
    RsaSigner
        .verify(
            signed.as_bytes(),
            &Base64UrlSafeNoPadding::decode_to_vec(signature, None).unwrap(),
            &certificate
                .tbs_certificate
                .subject_pki
                .subject_public_key
                .data,
        )
        .unwrap();
    let claims: serde_json::Value = serde_json::from_slice(
        &Base64UrlSafeNoPadding::decode_to_vec(signed.split('.').nth(1).unwrap(), None).unwrap(),
    )
    .unwrap();
    assert_eq!(claims["iss"], SIGNER_CLIENT_ID);
    assert_eq!(claims["sub"], SIGNER_CLIENT_ID);
    assert_eq!(claims["aud"], format!("{}/token", mock_server.uri()));
}

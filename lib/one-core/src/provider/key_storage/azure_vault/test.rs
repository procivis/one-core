use std::collections::HashMap;
use std::sync::Arc;

use one_crypto::{CryptoProvider, CryptoProviderImpl, Hasher, MockHasher};
use secrecy::SecretString;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{
    body_json, body_string_contains, header, method, path, path_regex, query_param,
};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::dto::AzureHsmGetTokenResponse;
use super::{AzureVaultKeyProvider, Params};
use crate::model::key::Key;
use crate::provider::http_client::reqwest_client::ReqwestClient;
use crate::provider::key_storage::error::KeyStorageError;
use crate::provider::key_storage::KeyStorage;

fn get_params(mock_base_url: String) -> Params {
    Params {
        ad_tenant_id: Default::default(),
        client_id: Default::default(),
        client_secret: "secret".to_string(),
        oauth_service_url: mock_base_url.parse().unwrap(),
        vault_url: mock_base_url.parse().unwrap(),
    }
}

async fn get_token_mock(mock_server: &MockServer, expires_in: i64, expect: u64) {
    let token = AzureHsmGetTokenResponse {
        token_type: "Bearer".to_string(),
        expires_in,
        access_token: SecretString::from("mock_access_token"),
    };

    wiremock::Mock::given(method(Method::POST))
        .and(path(
            "/00000000-0000-0000-0000-000000000000/oauth2/v2.0/token",
        ))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .and(body_string_contains(
            [
                "client_id=00000000-0000-0000-0000-000000000000",
                "client_secret=secret",
                "grant_type=client_credentials",
                "scope",
            ]
            .join("&"),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(token)))
        .expect(expect)
        .mount(mock_server)
        .await;
}

async fn generate_key_mock(mock_server: &MockServer, expect: u64) {
    Mock::given(method(Method::POST))
    .and(path_regex(r"/keys/.*/create"))
    .and(header("content-type", "application/json"))
    .and(body_json(json!({
         "kty":"EC-HSM",
         "crv":"P-256",
         "key_ops":["sign","verify"]
        })))
    .respond_with(ResponseTemplate::new(200).set_body_json(json!(
        {
          "key": {
            "kid": "https://one-dev.vault.azure.net/keys/testing-1/243dbdcdae4f4fe98fe65e6b337df35f",
            "kty": "EC-HSM",
            "key_ops": [
              "sign",
              "verify"
            ],
            "crv": "P-256",
            "x": "f-63txJ1oUcLxdNm9vVz4UCOJt7wZ5mwCuRSvcOmwP8",
            "y": "nm-KIBvKrBG8ubtytdBuLcgezEJ14YN1Pb6Wj8LoTr8"
          },
          "attributes": {
            "enabled": true,
            "created": 1700655189,
            "updated": 1700655189,
            "recoveryLevel": "CustomizedRecoverable+Purgeable",
            "recoverableDays": 7,
            "exportable": false
          }
        }
    )))
    .expect(expect)
    .mount(mock_server).await;
}

async fn sign_mock(mock_server: &MockServer, expect: u64) {
    Mock::given(path("/keys/uuid/keyid/sign"))
        .and(header("content-type", "application/json"))
        .and(query_param("api-version", "7.4"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
              "kid": "/keys/uuid/keyid",
              "value": "c2lnbmVkX21lc3NhZ2U"
            }
        )))
        .expect(expect)
        .mount(mock_server)
        .await;
}

fn get_crypto(hashers: Vec<(String, Arc<dyn Hasher>)>) -> Arc<dyn CryptoProvider> {
    Arc::new(CryptoProviderImpl::new(
        HashMap::from_iter(hashers),
        HashMap::new(),
    ))
}

#[tokio::test]
async fn test_azure_vault_generate() {
    let mock_server = MockServer::start().await;

    get_token_mock(&mock_server, 3600, 1).await;
    generate_key_mock(&mock_server, 2).await;

    let vault = AzureVaultKeyProvider::new(
        get_params(mock_server.uri()),
        get_crypto(vec![]),
        Arc::new(ReqwestClient::default()),
    );
    vault
        .generate(Uuid::new_v4().into(), "ECDSA")
        .await
        .unwrap();
    vault
        .generate(Uuid::new_v4().into(), "ECDSA")
        .await
        .unwrap();
}

#[tokio::test]
async fn test_azure_vault_generate_expired_key_causes_second_token_request() {
    let mock_server = MockServer::start().await;

    get_token_mock(&mock_server, -5, 2).await;
    generate_key_mock(&mock_server, 2).await;

    let vault = AzureVaultKeyProvider::new(
        get_params(mock_server.uri()),
        get_crypto(vec![]),
        Arc::new(ReqwestClient::default()),
    );
    vault
        .generate(Uuid::new_v4().into(), "ECDSA")
        .await
        .unwrap();
    vault
        .generate(Uuid::new_v4().into(), "ECDSA")
        .await
        .unwrap();
}

#[tokio::test]
async fn test_azure_vault_generate_failed_unsupported_key_type() {
    let vault = AzureVaultKeyProvider::new(
        get_params("http://127.0.0.1".to_string()),
        get_crypto(vec![]),
        Arc::new(ReqwestClient::default()),
    );
    let result = vault.generate(Uuid::new_v4().into(), "UNKNOWN").await;
    assert!(matches!(
        result,
        Err(KeyStorageError::UnsupportedKeyType { .. })
    ));
}

#[tokio::test]
async fn test_azure_vault_sign() {
    let mock_server = MockServer::start().await;

    get_token_mock(&mock_server, 3600, 1).await;
    sign_mock(&mock_server, 1).await;
    let mut hasher_mock = MockHasher::default();
    hasher_mock
        .expect_hash_base64_url()
        .times(1)
        .returning(|_| Ok("123".to_string()));

    let key_reference = format!("{}/keys/uuid/keyid", mock_server.uri());

    let vault = AzureVaultKeyProvider::new(
        get_params(mock_server.uri()),
        get_crypto(vec![("sha-256".to_string(), Arc::new(hasher_mock))]),
        Arc::new(ReqwestClient::default()),
    );
    let key_handle = vault
        .key_handle(&Key {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            public_key: vec![],
            name: "".to_string(),
            key_reference: key_reference.as_bytes().to_vec(),
            storage_type: "".to_string(),
            key_type: "".to_string(),
            organisation: None,
        })
        .unwrap();
    let result = key_handle.sign("message_to_sign".as_bytes()).await.unwrap();

    assert_eq!("signed_message".as_bytes(), result);
}

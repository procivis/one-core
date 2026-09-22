use std::sync::Arc;

use secrecy::SecretString;
use serde_json::json;
use similar_asserts::assert_eq;
use standardized_types::jwk::{PrivateJwk, PrivateJwkEc};
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{
    body_json, body_string_contains, header, method, path, path_regex, query_param,
};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::AzureVaultKeyProvider;
use super::dto::AzureHsmGetTokenResponse;
use crate::config::core_config::KeyAlgorithmType;
use crate::model::key::Key;
use crate::proto::http_client::reqwest_client::ReqwestClient;
use crate::provider::key_storage::KeyStorage;
use crate::provider::key_storage::error::KeyStorageError;
use crate::service::test_utilities::dummy_organisation;

fn get_params(mock_base_url: String) -> serde_json::Value {
    json!({
        "clientId": "00000000-0000-0000-0000-000000000000",
        "clientSecret": "secret",
        "adTenantId": "00000000-0000-0000-0000-000000000000",
        "oauthServiceUrl": mock_base_url,
        "vaultUrl": mock_base_url,
    })
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

async fn import_key_mock(mock_server: &MockServer, expect: u64) {
    Mock::given(method(Method::PUT))
        .and(path_regex(r"/keys/.*"))
        .and(header("content-type", "application/json"))
        .and(body_json(json!({
            "key": {
                "kty": "EC-HSM",
                "crv": "P-256",
                "x": "r1U6-8dqlyj-_CwYft6kxx9MCfInQYCoUwKiP579c3w",
                "y": "u_EMmvFmfsUjDmDY2kBhZPK0tyycAylkoY-PLAUD1WU",
                "d": "_M90X3GfBZoFDBZHZsMQszc2a92dCorIJBlytnmkKEM"
            },
            "Hsm": true
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
        {
          "key": {
            "kid": "https://one-dev.vault.azure.net/keys/testing-1/13ae667d-392b-4c00-8896-079909fe85d7",
            "kty": "EC-HSM",
            "crv": "P-256",
            "key_ops": [],
            "x": "r1U6-8dqlyj-_CwYft6kxx9MCfInQYCoUwKiP579c3w",
            "y": "u_EMmvFmfsUjDmDY2kBhZPK0tyycAylkoY-PLAUD1WU",
            "d": "_M90X3GfBZoFDBZHZsMQszc2a92dCorIJBlytnmkKEM"
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

#[tokio::test]
async fn test_azure_vault_generate() {
    let mock_server = MockServer::start().await;

    get_token_mock(&mock_server, 3600, 1).await;
    generate_key_mock(&mock_server, 2).await;

    let vault = AzureVaultKeyProvider::new(
        "azure_vault",
        get_params(mock_server.uri()),
        Arc::new(ReqwestClient::default()),
    )
    .unwrap();
    vault
        .generate(Uuid::new_v4().into(), KeyAlgorithmType::Ecdsa, json!({}))
        .await
        .unwrap();
    vault
        .generate(Uuid::new_v4().into(), KeyAlgorithmType::Ecdsa, json!({}))
        .await
        .unwrap();
}

#[tokio::test]
async fn test_azure_vault_generate_expired_key_causes_second_token_request() {
    let mock_server = MockServer::start().await;

    get_token_mock(&mock_server, -5, 2).await;
    generate_key_mock(&mock_server, 2).await;

    let vault = AzureVaultKeyProvider::new(
        "azure_vault",
        get_params(mock_server.uri()),
        Arc::new(ReqwestClient::default()),
    )
    .unwrap();
    vault
        .generate(Uuid::new_v4().into(), KeyAlgorithmType::Ecdsa, json!({}))
        .await
        .unwrap();
    vault
        .generate(Uuid::new_v4().into(), KeyAlgorithmType::Ecdsa, json!({}))
        .await
        .unwrap();
}

#[tokio::test]
async fn test_azure_vault_generate_failed_unsupported_key_type() {
    let vault = AzureVaultKeyProvider::new(
        "azure_vault",
        get_params("http://127.0.0.1".to_string()),
        Arc::new(ReqwestClient::default()),
    )
    .unwrap();
    let result = vault
        .generate(Uuid::new_v4().into(), KeyAlgorithmType::MlDsa, json!({}))
        .await;
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

    let key_reference = format!("{}/keys/uuid/keyid", mock_server.uri());

    let vault = AzureVaultKeyProvider::new(
        "azure_vault",
        get_params(mock_server.uri()),
        Arc::new(ReqwestClient::default()),
    )
    .unwrap();
    let key_handle = vault
        .key_handle(&Key {
            autogenerated: false,
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            public_key: vec![],
            name: "".to_string(),
            key_reference: Some(key_reference.as_bytes().to_vec()),
            storage_type: "".to_string(),
            key_type: "".to_string(),
            organisation: dummy_organisation(None).into(),
        })
        .unwrap();
    let result = key_handle.sign("message_to_sign".as_bytes()).await.unwrap();

    assert_eq!("signed_message".as_bytes(), result);
}

#[tokio::test]
async fn test_azure_vault_import() {
    let mock_server = MockServer::start().await;

    get_token_mock(&mock_server, 3600, 1).await;
    import_key_mock(&mock_server, 1).await;

    let vault = AzureVaultKeyProvider::new(
        "azure_vault",
        get_params(mock_server.uri()),
        Arc::new(ReqwestClient::default()),
    )
    .unwrap();

    vault
        .import(
            Uuid::new_v4().into(),
            KeyAlgorithmType::Ecdsa,
            PrivateJwk::Ec(PrivateJwkEc {
                r#use: None,
                kid: Some("13ae667d-392b-4c00-8896-079909fe85d7".to_string()),
                crv: "P-256".to_string(),
                x: "r1U6-8dqlyj-_CwYft6kxx9MCfInQYCoUwKiP579c3w".to_string(),
                y: Some("u_EMmvFmfsUjDmDY2kBhZPK0tyycAylkoY-PLAUD1WU".to_string()),
                d: "_M90X3GfBZoFDBZHZsMQszc2a92dCorIJBlytnmkKEM".into(),
            }),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_azure_vault_import_unsupported_key_type() {
    let vault = AzureVaultKeyProvider::new(
        "azure_vault",
        get_params("http://127.0.0.1".to_string()),
        Arc::new(ReqwestClient::default()),
    )
    .unwrap();

    let result = vault
        .import(
            Uuid::new_v4().into(),
            KeyAlgorithmType::Eddsa,
            PrivateJwk::Okp(PrivateJwkEc {
                r#use: None,
                kid: Some("13ae667d-392b-4c00-8896-079909fe85d7".to_string()),
                crv: "P-256".to_string(),
                x: "r1U6-8dqlyj-_CwYft6kxx9MCfInQYCoUwKiP579c3w".to_string(),
                y: Some("u_EMmvFmfsUjDmDY2kBhZPK0tyycAylkoY-PLAUD1WU".to_string()),
                d: "_M90X3GfBZoFDBZHZsMQszc2a92dCorIJBlytnmkKEM".into(),
            }),
        )
        .await;
    assert!(matches!(
        result,
        Err(KeyStorageError::UnsupportedKeyType { .. })
    ));
}

#[tokio::test]
async fn test_azure_vault_import_jwk_invalid_key_type() {
    let vault = AzureVaultKeyProvider::new(
        "azure_vault",
        get_params("http://127.0.0.1".to_string()),
        Arc::new(ReqwestClient::default()),
    )
    .unwrap();

    let result = vault
        .import(
            Uuid::new_v4().into(),
            KeyAlgorithmType::Ecdsa,
            PrivateJwk::Okp(PrivateJwkEc {
                r#use: None,
                kid: Some("13ae667d-392b-4c00-8896-079909fe85d7".to_string()),
                crv: "P-256".to_string(),
                x: "r1U6-8dqlyj-_CwYft6kxx9MCfInQYCoUwKiP579c3w".to_string(),
                y: Some("u_EMmvFmfsUjDmDY2kBhZPK0tyycAylkoY-PLAUD1WU".to_string()),
                d: "_M90X3GfBZoFDBZHZsMQszc2a92dCorIJBlytnmkKEM".into(),
            }),
        )
        .await;
    assert!(matches!(
        result,
        Err(KeyStorageError::InvalidKeyAlgorithm(_))
    ));
}

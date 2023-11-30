use super::{dto::AzureHsmGetTokenResponse, AzureVaultKeyProvider, Params};

use std::collections::HashMap;
use std::sync::Arc;

use httpmock::Method::POST;
use httpmock::{Mock, MockServer, Regex};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    crypto::{
        hasher::{Hasher, MockHasher},
        CryptoProvider, CryptoProviderImpl,
    },
    model::key::Key,
    provider::key_storage::KeyStorage,
};

fn get_params(mock_base_url: String) -> Params {
    Params {
        ad_tenant_id: Default::default(),
        client_id: Default::default(),
        client_secret: "secret".to_string(),
        oauth_service_url: mock_base_url.parse().unwrap(),
        vault_url: mock_base_url.parse().unwrap(),
    }
}

async fn get_token_mock(mock_server: &MockServer, expires_in: i64) -> Mock {
    let token = AzureHsmGetTokenResponse {
        token_type: "Bearer".to_string(),
        expires_in,
        access_token: "mock_access_token".to_string(),
    };

    mock_server
        .mock_async(|when, then| {
            when.method(POST)
                .path("//00000000-0000-0000-0000-000000000000/oauth2/v2.0/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .x_www_form_urlencoded_tuple("client_id", "00000000-0000-0000-0000-000000000000")
                .x_www_form_urlencoded_tuple("client_secret", "secret")
                .x_www_form_urlencoded_tuple("grant_type", "client_credentials")
                .x_www_form_urlencoded_key_exists("scope");
            then.status(200).json_body(json!(token));
        })
        .await
}

async fn generate_key_mock(mock_server: &MockServer) -> Mock {
    mock_server
        .mock_async(|when, then| {
            when.method(POST)
                .path_matches(Regex::new("//keys/.*/create").unwrap())
                .body(r#"{"kty":"EC-HSM","crv":"P-256","key_ops":["sign","verify"]}"#)
                .header("Content-Type", "application/json");
            then.status(200).json_body(json!(
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
            ));
        })
        .await
}

async fn sign_mock(mock_server: &MockServer) -> Mock {
    mock_server
        .mock_async(|when, then| {
            when.method(POST)
                .path("/keys/uuid/keyid/sign")
                .query_param("api-version", "7.4")
                .header("content-type", "application/json");
            then.status(200).json_body(json!(
                {
                  "kid": "/keys/uuid/keyid",
                  "value": "c2lnbmVkX21lc3NhZ2U"
                }
            ));
        })
        .await
}

fn get_crypto(
    hashers: Vec<(String, Arc<dyn Hasher + Send + Sync>)>,
) -> Arc<dyn CryptoProvider + Send + Sync> {
    Arc::new(CryptoProviderImpl::new(
        HashMap::from_iter(hashers),
        HashMap::new(),
    ))
}

#[tokio::test]
async fn test_azure_vault_generate() {
    let mock_server = MockServer::start_async().await;

    let token_mock = get_token_mock(&mock_server, 3600).await;
    let key_mock = generate_key_mock(&mock_server).await;

    let vault = AzureVaultKeyProvider::new(get_params(mock_server.base_url()), get_crypto(vec![]));
    vault.generate(&Uuid::new_v4(), "ES256").await.unwrap();
    vault.generate(&Uuid::new_v4(), "ES256").await.unwrap();

    token_mock.assert_async().await;
    key_mock.assert_hits_async(2).await;
}

#[tokio::test]
async fn test_azure_vault_generate_expired_key_causes_second_token_request() {
    let mock_server = MockServer::start_async().await;

    let token_mock = get_token_mock(&mock_server, -5).await;
    let key_mock = generate_key_mock(&mock_server).await;

    let vault = AzureVaultKeyProvider::new(get_params(mock_server.base_url()), get_crypto(vec![]));
    vault.generate(&Uuid::new_v4(), "ES256").await.unwrap();
    vault.generate(&Uuid::new_v4(), "ES256").await.unwrap();

    token_mock.assert_hits_async(2).await;
    key_mock.assert_hits_async(2).await;
}

#[tokio::test]
async fn test_azure_vault_sign() {
    let mock_server = MockServer::start_async().await;

    let token_mock = get_token_mock(&mock_server, 3600).await;
    let sign_mock = sign_mock(&mock_server).await;
    let mut hasher_mock = MockHasher::default();
    hasher_mock
        .expect_hash_base64()
        .times(1)
        .returning(|_| Ok("123".to_string()));

    let key_reference = format!("{}/keys/uuid/keyid", mock_server.base_url());

    let vault = AzureVaultKeyProvider::new(
        get_params(mock_server.base_url()),
        get_crypto(vec![("sha-256".to_string(), Arc::new(hasher_mock))]),
    );
    let result = vault
        .sign(
            &Key {
                id: Default::default(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                public_key: vec![],
                name: "".to_string(),
                key_reference: key_reference.as_bytes().to_vec(),
                storage_type: "".to_string(),
                key_type: "".to_string(),
                organisation: None,
            },
            "message_to_sign",
        )
        .await
        .unwrap();

    assert_eq!("signed_message".as_bytes(), result);

    token_mock.assert_async().await;
    sign_mock.assert_async().await;
}

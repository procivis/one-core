use super::{dto::AzureHsmGetTokenResponse, AzureVaultKeyProvider, Params};

use httpmock::Method::POST;
use httpmock::{Mock, MockServer, Regex};
use serde_json::json;
use uuid::Uuid;

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

#[tokio::test]
async fn test_azure_vault_generate() {
    let mock_server = MockServer::start_async().await;

    let token_mock = get_token_mock(&mock_server, 3600).await;
    let key_mock = generate_key_mock(&mock_server).await;

    let vault = AzureVaultKeyProvider::new(get_params(mock_server.base_url()));
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

    let vault = AzureVaultKeyProvider::new(get_params(mock_server.base_url()));
    vault.generate(&Uuid::new_v4(), "ES256").await.unwrap();
    vault.generate(&Uuid::new_v4(), "ES256").await.unwrap();

    token_mock.assert_hits_async(2).await;
    key_mock.assert_hits_async(2).await;
}

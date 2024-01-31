use core_server::router::start_server;
use serde_json::Value;

use crate::{fixtures, utils};

#[tokio::test]
async fn test_get_credential_issuer_metadata() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let credential_schema =
        fixtures::create_credential_schema(&db_conn, "test", &organisation, "NONE").await;

    // WHEN
    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn).await });

    let url = format!(
        "{base_url}/ssi/oidc-issuer/v1/{}/.well-known/openid-credential-issuer",
        credential_schema.id
    );

    let resp = utils::client().get(url).send().await.unwrap();

    // THEN
    assert_eq!(resp.status(), 200);

    let resp: Value = resp.json().await.unwrap();

    let issuer = format!("{base_url}/ssi/oidc-issuer/v1/{}", credential_schema.id);

    assert_eq!(issuer, resp["credential_issuer"].as_str().unwrap());
    assert_eq!(
        format!("{issuer}/credential"),
        resp["credential_endpoint"].as_str().unwrap()
    );
    assert!(!resp["credentials_supported"].as_array().unwrap().is_empty());
}

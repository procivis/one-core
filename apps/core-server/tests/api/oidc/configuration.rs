use serde_json::Value;
use similar_asserts::assert_eq;

use crate::utils::server::run_server;
use crate::{fixtures, utils};

#[tokio::test]
async fn test_get_issuer_configuration_draft13() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let credential_schema = fixtures::create_credential_schema(&db_conn, &organisation, None).await;

    // WHEN
    let _handle = run_server(listener, config, &db_conn).await;

    let url = format!(
        "{base_url}/ssi/openid4vci/draft-13/{}/.well-known/openid-configuration",
        credential_schema.id
    );
    let resp = utils::client().get(url).send().await.unwrap();

    // THEN
    assert_eq!(resp.status(), 200);

    let resp: Value = resp.json().await.unwrap();

    let issuer = format!(
        "{base_url}/ssi/openid4vci/draft-13/{}",
        credential_schema.id
    );

    assert_eq!(issuer, resp["issuer"].as_str().unwrap());
    assert_eq!(
        format!("{issuer}/authorize"),
        resp["authorization_endpoint"].as_str().unwrap()
    );
    assert_eq!(
        format!("{issuer}/token"),
        resp["token_endpoint"].as_str().unwrap()
    );
    assert_eq!(format!("{issuer}/jwks"), resp["jwks_uri"].as_str().unwrap());
}

#[tokio::test]
async fn test_get_issuer_configuration_final1_0() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let credential_schema = fixtures::create_credential_schema(&db_conn, &organisation, None).await;

    // WHEN
    let _handle = run_server(listener, config, &db_conn).await;

    let url = format!(
        "{base_url}/.well-known/openid-configuration/ssi/openid4vci/final-1.0/{}",
        credential_schema.id
    );

    let resp = utils::client().get(url).send().await.unwrap();

    // THEN
    assert_eq!(resp.status(), 200);

    let resp: Value = resp.json().await.unwrap();

    let issuer = format!(
        "{base_url}/ssi/openid4vci/final-1.0/{}",
        credential_schema.id
    );

    assert_eq!(issuer, resp["issuer"].as_str().unwrap());
    assert_eq!(
        format!("{issuer}/authorize"),
        resp["authorization_endpoint"].as_str().unwrap()
    );
    assert_eq!(
        format!("{issuer}/token"),
        resp["token_endpoint"].as_str().unwrap()
    );
    assert_eq!(format!("{issuer}/jwks"), resp["jwks_uri"].as_str().unwrap());
}

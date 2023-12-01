use core_server::router::start_server;
use one_core::model::did::{DidType, KeyRole};
use serde_json::Value;

use crate::{fixtures, utils};

#[tokio::test]
async fn test_get_did_web_document_es256_success() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did_web(&db_conn, &organisation, false, DidType::Local).await;
    let key = fixtures::create_es256_key(
        &db_conn,
        "ES256".to_string(),
        &organisation.id.to_string(),
        Some(did.id.clone()),
    )
    .await;
    fixtures::create_key_did(&db_conn, &did.id.to_string(), &key, KeyRole::Authentication).await;
    fixtures::create_key_did(&db_conn, &did.id.to_string(), &key, KeyRole::KeyAgreement).await;
    fixtures::create_key_did(
        &db_conn,
        &did.id.to_string(),
        &key,
        KeyRole::AssertionMethod,
    )
    .await;

    // WHEN
    let url = format!("{base_url}/ssi/did-web/v1/{}/did.json", did.id);

    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn).await });

    let resp = utils::client().get(url).send().await.unwrap();

    // THEN
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json().await.unwrap();
    assert_eq!(
        resp["assertionMethod"][0].as_str().unwrap(),
        resp["verificationMethod"][0]["id"].as_str().unwrap()
    );
    assert_eq!(
        resp["verificationMethod"][0]["publicKeyJwk"]["crv"]
            .as_str()
            .unwrap(),
        "P-256"
    );
    assert_eq!(
        resp["verificationMethod"][0]["publicKeyJwk"]["kty"]
            .as_str()
            .unwrap(),
        "EC"
    );
    assert_eq!(
        resp["verificationMethod"][0]["publicKeyJwk"]["x"]
            .as_str()
            .unwrap(),
        "1Epsq2U3GeRxiWv0OzUSlw51DpxqsodolnF65b8oBWA"
    );
    assert_eq!(
        resp["verificationMethod"][0]["publicKeyJwk"]["y"]
            .as_str()
            .unwrap(),
        "po4io_aLclVOpKyEz1J7EEKJFfZOxfUqSQdXzWvaeo4"
    );
}

#[tokio::test]
async fn test_get_did_web_document_eddsa_success() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did_web(&db_conn, &organisation, false, DidType::Local).await;
    let key = fixtures::create_eddsa_key(
        &db_conn,
        "EDDSA".to_string(),
        &organisation.id.to_string(),
        &did.id,
    )
    .await;
    fixtures::create_key_did(&db_conn, &did.id.to_string(), &key, KeyRole::Authentication).await;
    fixtures::create_key_did(&db_conn, &did.id.to_string(), &key, KeyRole::KeyAgreement).await;
    fixtures::create_key_did(
        &db_conn,
        &did.id.to_string(),
        &key,
        KeyRole::AssertionMethod,
    )
    .await;

    // WHEN
    let url = format!("{base_url}/ssi/did-web/v1/{}/did.json", did.id);

    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn).await });

    let resp = utils::client().get(url).send().await.unwrap();

    // THEN
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json().await.unwrap();
    assert_eq!(
        resp["assertionMethod"][0].as_str().unwrap(),
        resp["verificationMethod"][0]["id"].as_str().unwrap()
    );
    assert_eq!(
        resp["verificationMethod"][0]["publicKeyJwk"]["crv"]
            .as_str()
            .unwrap(),
        "Ed25519"
    );
    assert_eq!(
        resp["verificationMethod"][0]["publicKeyJwk"]["kty"]
            .as_str()
            .unwrap(),
        "OKP"
    );
    assert_eq!(
        resp["verificationMethod"][0]["publicKeyJwk"]["x"]
            .as_str()
            .unwrap(),
        "O5OVii-jG3nCytu9N3iSh8wxeG7OhE7gXt09oas97nw"
    );
    assert!(resp["verificationMethod"][0]["publicKeyJwk"]["y"]
        .as_str()
        .is_none());
}

#[tokio::test]
async fn test_get_did_web_document_wrong_did_method() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did_key(&db_conn, &organisation).await;

    // WHEN
    let url = format!("{base_url}/ssi/did-web/v1/{}/did.json", did.id);

    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn).await });

    let resp = utils::client().get(url).send().await.unwrap();

    // THEN
    assert_eq!(resp.status(), 400)
}

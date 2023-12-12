use crate::fixtures::get_did_by_id;
use crate::{fixtures, utils};
use core_server::router::start_server;
use one_core::model::did::DidType;
use serde_json::{json, Value};
use shared_types::DidId;
use std::str::FromStr;

#[tokio::test]
async fn test_create_did_key_es256_success() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let key = fixtures::create_es256_key(&db_conn, &organisation).await;
    // WHEN
    let url = format!("{base_url}/api/did/v1");

    let db_conn_clone = db_conn.clone();
    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn_clone).await });

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "keys": {
            "assertion": [
              key.id
            ],
            "authentication": [
              key.id
            ],
            "capabilityDelegation": [
              key.id
            ],
            "capabilityInvocation": [
              key.id
            ],
            "keyAgreement": [
              key.id
            ]
          },
          "method": "KEY",
          "name": "test",
          "organisationId": organisation.id,
          "params": {}
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 201);
    let resp: Value = resp.json().await.unwrap();
    assert!(resp.get("id").is_some());

    let did = get_did_by_id(
        &db_conn,
        &DidId::from_str(resp["id"].as_str().unwrap()).unwrap(),
    )
    .await;
    assert_eq!(did.did_method, "KEY");
    assert_eq!(did.did_type, DidType::Local);
    assert!(did.did.as_str().starts_with("did:key:zDn"));
    let keys = did.keys.unwrap();
    assert_eq!(keys.len(), 5);
    for k in keys {
        assert_eq!(k.key.id, key.id);
    }
}

#[tokio::test]
async fn test_create_did_key_eddsa_success() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let key = fixtures::create_eddsa_key(&db_conn, &organisation).await;
    // WHEN
    let url = format!("{base_url}/api/did/v1");

    let db_conn_clone = db_conn.clone();
    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn_clone).await });

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "keys": {
            "assertion": [
              key.id
            ],
            "authentication": [
              key.id
            ],
            "capabilityDelegation": [
              key.id
            ],
            "capabilityInvocation": [
              key.id
            ],
            "keyAgreement": [
              key.id
            ]
          },
          "method": "KEY",
          "name": "test",
          "organisationId": organisation.id,
          "params": {}
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 201);
    let resp: Value = resp.json().await.unwrap();
    assert!(resp.get("id").is_some());

    let did = get_did_by_id(
        &db_conn,
        &DidId::from_str(resp["id"].as_str().unwrap()).unwrap(),
    )
    .await;
    assert_eq!(did.did_method, "KEY");
    assert_eq!(did.did_type, DidType::Local);
    assert!(did.did.as_str().starts_with("did:key:z6Mk"));
    let keys = did.keys.unwrap();
    assert_eq!(keys.len(), 5);
    for k in keys {
        assert_eq!(k.key.id, key.id);
    }
}

#[tokio::test]
async fn test_create_did_web_success() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let key = fixtures::create_key(&db_conn, &organisation, None).await;
    // WHEN
    let url = format!("{base_url}/api/did/v1");

    let db_conn_clone = db_conn.clone();
    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn_clone).await });

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "keys": {
            "assertion": [
              key.id
            ],
            "authentication": [
              key.id
            ],
            "capabilityDelegation": [
              key.id
            ],
            "capabilityInvocation": [
              key.id
            ],
            "keyAgreement": [
              key.id
            ]
          },
          "method": "WEB",
          "name": "test",
          "organisationId": organisation.id,
          "params": {}
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 201);
    let resp: Value = resp.json().await.unwrap();
    assert!(resp.get("id").is_some());

    let did = get_did_by_id(
        &db_conn,
        &DidId::from_str(resp["id"].as_str().unwrap()).unwrap(),
    )
    .await;
    assert_eq!(did.did_method, "WEB");
    assert_eq!(did.did_type, DidType::Local);
    assert!(did.did.as_str().starts_with("did:web"));
    let keys = did.keys.unwrap();
    assert_eq!(keys.len(), 5);
    for k in keys {
        assert_eq!(k.key.id, key.id);
    }
}

#[tokio::test]
async fn test_create_did_jwk_success() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let key = fixtures::create_eddsa_key(&db_conn, &organisation).await;
    // WHEN
    let url = format!("{base_url}/api/did/v1");

    let db_conn_clone = db_conn.clone();
    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn_clone).await });

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "keys": {
            "assertion": [
              key.id
            ],
            "authentication": [
              key.id
            ],
            "capabilityDelegation": [
              key.id
            ],
            "capabilityInvocation": [
              key.id
            ],
            "keyAgreement": [
              key.id
            ]
          },
          "method": "JWK",
          "name": "test",
          "organisationId": organisation.id,
          "params": {}
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 201);
    let resp: Value = resp.json().await.unwrap();
    assert!(resp.get("id").is_some());

    let did = get_did_by_id(
        &db_conn,
        &DidId::from_str(resp["id"].as_str().unwrap()).unwrap(),
    )
    .await;
    assert_eq!(did.did_method, "JWK");
    assert_eq!(did.did_type, DidType::Local);
    assert!(did.did.as_str().starts_with("did:jwk"));
    let keys = did.keys.unwrap();
    assert_eq!(keys.len(), 5);
    for k in keys {
        assert_eq!(k.key.id, key.id);
    }
}

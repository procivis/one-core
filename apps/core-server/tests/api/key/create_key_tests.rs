use std::str::FromStr;

use core_server::router::start_server;
use reqwest::StatusCode;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{fixtures, utils};

#[tokio::test]
async fn test_create_key_es256() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;

    // WHEN
    let url = format!("{base_url}/api/key/v1");

    let db_conn_clone = db_conn.clone();
    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn_clone).await });

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "keyParams": {},
          "keyType": "ES256",
          "name": "ESTEST",
          "organisationId": organisation.id,
          "storageParams": {},
          "storageType": "INTERNAL"
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp: Value = resp.json().await.unwrap();
    let id = Uuid::from_str(resp["id"].as_str().unwrap()).unwrap();

    let key = fixtures::get_key(&db_conn, &id).await;

    assert_eq!(key.name, "ESTEST");
    assert_eq!(key.key_type, "ES256");
    assert!(!key.public_key.is_empty());
    assert_eq!(key.organisation.unwrap().id, organisation.id);
}

#[tokio::test]
async fn test_create_key_eddsa() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;

    // WHEN
    let url = format!("{base_url}/api/key/v1");

    let db_conn_clone = db_conn.clone();
    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn_clone).await });

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "keyParams": {},
          "keyType": "EDDSA",
          "name": "EDDSATEST",
          "organisationId": organisation.id,
          "storageParams": {},
          "storageType": "INTERNAL"
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp: Value = resp.json().await.unwrap();
    let id = Uuid::from_str(resp["id"].as_str().unwrap()).unwrap();

    let key = fixtures::get_key(&db_conn, &id).await;

    assert_eq!(key.name, "EDDSATEST");
    assert_eq!(key.key_type, "EDDSA");
    assert!(!key.public_key.is_empty());
    assert_eq!(key.organisation.unwrap().id, organisation.id);
}

#[tokio::test]
async fn test_create_invalid_type() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;

    // WHEN
    let url = format!("{base_url}/api/key/v1");

    let db_conn_clone = db_conn.clone();
    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn_clone).await });

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "keyParams": {},
          "keyType": "INVALID",
          "name": "TEST",
          "organisationId": organisation.id,
          "storageParams": {},
          "storageType": "INTERNAL"
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_create_invalid_organisation() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;

    // WHEN
    let url = format!("{base_url}/api/key/v1");

    let db_conn_clone = db_conn.clone();
    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn_clone).await });

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "keyParams": {},
          "keyType": "EDDSA",
          "name": "TEST",
          "organisationId": Uuid::new_v4(),
          "storageParams": {},
          "storageType": "INTERNAL"
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

use core_server::router::start_server;
use httpmock::MockServer;
use one_core::model::did::DidType;
use serde_json::json;
use uuid::Uuid;

use crate::{fixtures, utils};

#[tokio::test]
async fn test_update_did_cannot_deactivate_did_key() {
    // GIVEN
    let mock_server = MockServer::start_async().await;
    let config = fixtures::create_config(mock_server.base_url());
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did_key(&db_conn, &organisation).await;

    // WHEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let url = format!("{base_url}/api/did/v1/{}", did.id);

    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn).await });

    let resp = utils::client()
        .patch(url)
        .bearer_auth("test")
        .json(&json!({
            "deactivated": true,
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 400)
}

#[tokio::test]
async fn test_update_did_deactivates_local_did_web() {
    // GIVEN
    let mock_server = MockServer::start_async().await;
    let config = fixtures::create_config(mock_server.base_url());
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did_web(&db_conn, &organisation, false, DidType::Local).await;

    // WHEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let url = format!("{base_url}/api/did/v1/{}", did.id);

    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn).await });

    let resp = utils::client()
        .patch(url)
        .bearer_auth("test")
        .json(&json!({
            "deactivated": true,
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 204)
}

#[tokio::test]
async fn test_update_did_cannot_deactivate_remote_did_web() {
    // GIVEN
    let mock_server = MockServer::start_async().await;
    let config = fixtures::create_config(mock_server.base_url());
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did_web(&db_conn, &organisation, false, DidType::Remote).await;

    // WHEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let url = format!("{base_url}/api/did/v1/{}", did.id);

    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn).await });

    let resp = utils::client()
        .patch(url)
        .bearer_auth("test")
        .json(&json!({
            "deactivated": true,
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 400)
}

#[tokio::test]
async fn test_update_did_same_deactivated_status_as_requested() {
    // GIVEN
    let mock_server = MockServer::start_async().await;
    let config = fixtures::create_config(mock_server.base_url());
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did_web(&db_conn, &organisation, true, DidType::Local).await;

    // WHEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let url = format!("{base_url}/api/did/v1/{}", did.id);

    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn).await });

    let resp = utils::client()
        .patch(url)
        .bearer_auth("test")
        .json(&json!({
            "deactivated": true,
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 409);
}

#[tokio::test]
async fn test_update_did_not_found() {
    // GIVEN
    let mock_server = MockServer::start_async().await;
    let config = fixtures::create_config(mock_server.base_url());
    let db_conn = fixtures::create_db(&config).await;

    // WHEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let did_id = Uuid::new_v4();
    let url = format!("{base_url}/api/did/v1/{did_id}");

    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn).await });

    let resp = utils::client()
        .patch(url)
        .bearer_auth("test")
        .json(&json!({
            "deactivated": true,
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 404);
}

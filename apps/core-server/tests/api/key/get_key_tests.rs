use core_server::router::start_server;
use reqwest::StatusCode;
use uuid::Uuid;

use crate::{fixtures, utils};

#[tokio::test]
async fn test_get_key_ok() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let key = fixtures::create_key(&db_conn, &organisation, None).await;

    // WHEN
    let url = format!("{base_url}/api/key/v1/{}", key.id);

    let db_conn_clone = db_conn.clone();
    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn_clone).await });

    let resp = utils::client()
        .get(url)
        .bearer_auth("test")
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), StatusCode::OK);

    let inserted_key = fixtures::get_key(&db_conn, &key.id).await;

    assert_eq!(key.id, inserted_key.id);
    assert_eq!(key.public_key, inserted_key.public_key);
}

#[tokio::test]
async fn test_get_key_not_found() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;

    // WHEN
    let url = format!("{base_url}/api/key/v1/{}", Uuid::new_v4());

    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn).await });

    let resp = utils::client()
        .get(url)
        .bearer_auth("test")
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 404);
}

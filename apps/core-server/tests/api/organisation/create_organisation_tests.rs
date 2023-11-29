use crate::{fixtures, utils};
use core_server::router::start_server;
use serde_json::{json, Value};
use uuid::Uuid;

#[tokio::test]
async fn test_create_organisation_success_id_set() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;
    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn).await });

    // WHEN
    let url = format!("{base_url}/api/organisation/v1");
    let organisation_id = Uuid::new_v4();
    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "id": organisation_id
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 201);
    let resp: Value = resp.json().await.unwrap();
    assert_eq!(resp["id"].as_str().unwrap(), organisation_id.to_string());
}

#[tokio::test]
async fn test_create_organisation_success_id_not_set() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;

    let db_conn_clone = db_conn.clone();
    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn_clone).await });

    // WHEN
    let url = format!("{base_url}/api/organisation/v1");
    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({}))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 201);
    let resp: Value = resp.json().await.unwrap();

    fixtures::get_organisation(
        &db_conn,
        &Uuid::parse_str(resp["id"].as_str().unwrap()).unwrap(),
    )
    .await;
}

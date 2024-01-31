use core_server::router::start_server;
use reqwest::StatusCode;
use serde_json::Value;

use crate::{
    fixtures::{self, TestingKeyParams},
    utils,
};

#[tokio::test]
async fn test_get_keys_ok() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let key1 = fixtures::create_key(
        &db_conn,
        &organisation,
        Some(TestingKeyParams {
            name: Some("name123".to_string()),
            ..Default::default()
        }),
    )
    .await;
    let key2 = fixtures::create_key(
        &db_conn,
        &organisation,
        Some(TestingKeyParams {
            name: Some("name321".to_string()),
            ..Default::default()
        }),
    )
    .await;

    _ = fixtures::create_key(
        &db_conn,
        &organisation,
        Some(TestingKeyParams {
            name: Some("test123".to_string()),
            ..Default::default()
        }),
    )
    .await;

    // WHEN
    let url = format!(
        "{base_url}/api/key/v1?page=0&pageSize=10&organisationId={}&name=name&sort=name",
        organisation.id
    );

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

    let resp: Value = resp.json().await.unwrap();
    let values = resp["values"].as_array().unwrap();

    assert_eq!(2, values.len());
    let key1_id = values[0]["id"].as_str().unwrap().parse().unwrap();
    let key2_name: String = values[1]["name"].as_str().unwrap().parse().unwrap();
    assert_eq!(key1.id, key1_id);
    assert_eq!(key2.name, key2_name);
}

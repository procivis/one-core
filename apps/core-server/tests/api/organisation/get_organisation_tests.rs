use core_server::router::start_server;
use serde_json::Value;

use crate::{fixtures, utils};

#[tokio::test]
async fn test_get_organisation_success() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn).await });

    // WHEN
    let url = format!("{base_url}/api/organisation/v1/{}", organisation.id);
    let resp = utils::client()
        .get(url)
        .bearer_auth("test")
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json().await.unwrap();

    assert_eq!(resp["id"].as_str().unwrap(), organisation.id.to_string());
    assert!(resp["createdDate"].is_string());
    assert!(resp["lastModified"].is_string());
}

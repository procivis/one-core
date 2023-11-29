use core_server::router::start_server;
use serde_json::Value;

use crate::{fixtures, utils};

#[tokio::test]
async fn test_list_organisation_success() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;

    for _ in 1..15 {
        fixtures::create_organisation(&db_conn).await;
    }

    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn).await });

    // WHEN
    let url = format!("{base_url}/api/organisation/v1");
    let resp = utils::client()
        .get(url)
        .bearer_auth("test")
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json().await.unwrap();
    assert_eq!(resp.as_array().unwrap().len(), 14);
}

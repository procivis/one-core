use core_server::router::start_server;
use httpmock::MockServer;
use serde_json::Value;

use crate::{fixtures, utils};

#[tokio::test]
async fn test_get_credential_schema_success() {
    // GIVEN
    let mock_server = MockServer::start_async().await;
    let config = fixtures::create_config(mock_server.base_url());
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;

    let credential_schema = fixtures::create_credential_schema(
        &db_conn,
        "test schema",
        &organisation,
        "STATUSLIST2021",
    )
    .await;

    // WHEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let url = format!(
        "{base_url}/api/credential-schema/v1/{}",
        credential_schema.id
    );

    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn).await });

    let resp = utils::client()
        .get(url)
        .bearer_auth("test")
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json().await.unwrap();

    assert_eq!(
        resp["id"].as_str().unwrap(),
        credential_schema.id.to_string()
    );
    assert_eq!(resp["claims"].as_array().unwrap().len(), 1);
    assert_eq!(resp["revocationMethod"].as_str().unwrap(), "STATUSLIST2021");
}

use core_server::router::start_server;
use httpmock::MockServer;
use serde_json::Value;
use uuid::Uuid;

use crate::{fixtures, utils};

#[tokio::test]
async fn test_get_list_credential_schema_success() {
    // GIVEN
    let mock_server = MockServer::start_async().await;
    let config = fixtures::create_config(mock_server.base_url());
    let db_conn = fixtures::create_db(&config).await;
    let organisation_id = fixtures::create_organisation(&db_conn).await;
    for i in 1..15 {
        let new_claim_schemas: Vec<(Uuid, &str, bool, u32, &str)> =
            vec![(Uuid::new_v4(), "firstName", true, 1, "STRING")];
        fixtures::create_credential_schema(
            &db_conn,
            &format!("test-{}", i),
            &organisation_id,
            &new_claim_schemas,
            "NONE",
        )
        .await;
    }
    // WHEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let url = format!(
        "{base_url}/api/credential-schema/v1?page={}&pageSize={}&organisationId={}",
        1, 8, organisation_id
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

    assert_eq!(resp["totalItems"].as_i64().unwrap(), 14);
    assert_eq!(resp["totalPages"].as_i64().unwrap(), 2);
    assert_eq!(resp["values"].as_array().unwrap().len(), 6);
}

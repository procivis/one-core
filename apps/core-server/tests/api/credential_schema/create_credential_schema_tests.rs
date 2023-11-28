use crate::{fixtures, utils};
use core_server::router::start_server;
use httpmock::MockServer;
use serde_json::{json, Value};

#[tokio::test]
async fn test_create_credential_schema_success() {
    // GIVEN
    let mock_server = MockServer::start_async().await;
    let config = fixtures::create_config(mock_server.base_url());
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;

    // WHEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let url = format!("{base_url}/api/credential-schema/v1");

    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn).await });

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "claims": [
            {
              "datatype": "STRING",
              "key": "firstName",
              "required": true
            }
          ],
          "format": "JWT",
          "name": "some credential schema",
          "organisationId": organisation.id,
          "revocationMethod": "STATUSLIST2021"
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 201);
    let resp: Value = resp.json().await.unwrap();

    assert!(resp.get("id").is_some());
    // TODO: Add additional checks when https://procivis.atlassian.net/browse/ONE-1133 is implemented
}

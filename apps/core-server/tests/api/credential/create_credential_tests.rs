use core_server::router::start_server;
use httpmock::MockServer;
use serde_json::{json, Value};

use crate::{fixtures, utils};

#[tokio::test]
async fn test_create_credential_success() {
    // GIVEN
    let mock_server = MockServer::start_async().await;
    let config = fixtures::create_config(mock_server.base_url());
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did_key(&db_conn, &organisation).await;

    let credential_schema =
        fixtures::create_credential_schema(&db_conn, "test", &organisation, "NONE").await;

    // WHEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let url = format!("{base_url}/api/credential/v1");

    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn).await });

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "credentialSchemaId": credential_schema.id,
          "transport": "OPENID4VC",
          "issuerDid": did.id,
          "claimValues": [
                {
                    "claimId": credential_schema.claim_schemas.unwrap().first().unwrap().schema.id,
                    "value": "some value"
                }
            ]
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

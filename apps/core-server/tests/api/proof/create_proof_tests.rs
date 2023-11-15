use core_server::router::start_server;
use httpmock::MockServer;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::fixtures::get_proof;
use crate::{fixtures, utils};

#[tokio::test]
async fn test_create_proof_success() {
    // GIVEN
    let mock_server = MockServer::start_async().await;
    let config = fixtures::create_config(mock_server.base_url());
    let db_conn = fixtures::create_db(&config).await;
    let organisation_id = fixtures::create_organisation(&db_conn).await;
    let did_id = fixtures::create_did_key(&db_conn, &organisation_id).await;
    let new_claim_schemas: Vec<(Uuid, &str, bool, u32, &str)> =
        vec![(Uuid::new_v4(), "firstName", true, 1, "STRING")];
    fixtures::create_credential_schema(&db_conn, "test", &organisation_id, &new_claim_schemas)
        .await;
    let proof_schema =
        fixtures::create_proof_schema(&db_conn, "test", &organisation_id, &new_claim_schemas).await;

    // WHEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let url = format!("{base_url}/api/proof-request/v1");

    let db_conn_check = db_conn.clone();
    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn).await });

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "proofSchemaId": proof_schema,
          "transport": "OPENID4VC",
          "verifierDid": did_id,
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 201);
    let resp: Value = resp.json().await.unwrap();

    assert!(resp.get("id").is_some());

    let proof = get_proof(&db_conn_check, resp["id"].as_str().unwrap()).await;
    assert_eq!(proof.transport, "OPENID4VC");
}

use core_server::router::start_server;

use serde_json::{json, Value};
use uuid::Uuid;

use crate::{fixtures, utils};

#[tokio::test]
async fn test_create_proof_schema_success() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;

    let organisation = fixtures::create_organisation(&db_conn).await;

    let credential_schema =
        fixtures::create_credential_schema(&db_conn, "test", &organisation, "NONE").await;
    let claim_schema = credential_schema
        .claim_schemas
        .unwrap()
        .first()
        .unwrap()
        .schema
        .to_owned();

    let db_conn_clone = db_conn.clone();
    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn_clone).await });

    // WHEN
    let url = format!("{base_url}/api/proof-schema/v1");
    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "claimSchemas": [
            {
              "id": claim_schema.id,
              "required": true
            }
          ],
          "expireDuration": 0,
          "name": "proof-schema-name",
          "organisationId": organisation.id
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 201);
    let resp: Value = resp.json().await.unwrap();
    assert!(resp.get("id").is_some());

    let proof_schema = fixtures::get_proof_schema(
        &db_conn,
        &Uuid::parse_str(resp["id"].as_str().unwrap()).unwrap(),
    )
    .await;
    assert_eq!(proof_schema.name, "proof-schema-name");
    assert_eq!(proof_schema.expire_duration, 0);
    assert_eq!(proof_schema.claim_schemas.unwrap().len(), 1);
}

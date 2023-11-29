use crate::{fixtures, utils};
use core_server::router::start_server;
use serde_json::{json, Value};
use uuid::Uuid;

#[tokio::test]
async fn test_create_credential_schema_success() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;

    // WHEN
    let url = format!("{base_url}/api/credential-schema/v1");

    let db_conn_clone = db_conn.clone();
    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn_clone).await });

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

    let credential_schema = fixtures::get_credential_schema(
        &db_conn,
        &Uuid::parse_str(resp["id"].as_str().unwrap()).unwrap(),
    )
    .await;
    assert_eq!(credential_schema.name, "some credential schema");
    assert_eq!(credential_schema.revocation_method, "STATUSLIST2021");
    assert_eq!(credential_schema.organisation.unwrap().id, organisation.id);
    assert_eq!(credential_schema.format, "JWT");
    assert_eq!(credential_schema.claim_schemas.unwrap().len(), 1);
}

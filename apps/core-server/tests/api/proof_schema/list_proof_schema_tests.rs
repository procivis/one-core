use core_server::router::start_server;

use serde_json::Value;

use crate::{fixtures, utils};

#[tokio::test]
async fn test_list_proof_schema_success() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url, None);
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

    for i in 1..15 {
        fixtures::create_proof_schema(
            &db_conn,
            &format!("test-{i}"),
            &organisation,
            &[(
                claim_schema.id,
                &claim_schema.key,
                true,
                &claim_schema.data_type,
            )],
        )
        .await;
    }

    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn).await });

    // WHEN
    let url = format!(
        "{base_url}/api/proof-schema/v1?page={}&pageSize={}&organisationId={}",
        0, 8, organisation.id
    );
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
    assert_eq!(resp["values"].as_array().unwrap().len(), 8);
}

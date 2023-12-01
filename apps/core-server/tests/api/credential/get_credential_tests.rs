use core_server::router::start_server;
use one_core::model::credential::CredentialStateEnum;
use serde_json::Value;

use crate::{fixtures, utils};

#[tokio::test]
async fn test_get_credential_success() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did_key(&db_conn, &organisation).await;
    let credential_schema =
        fixtures::create_credential_schema(&db_conn, "test", &organisation, "NONE").await;
    let credential = fixtures::create_credential(
        &db_conn,
        &credential_schema,
        CredentialStateEnum::Created,
        &did,
        None,
        None,
        "PROCIVIS_TEMPORARY",
    )
    .await;

    // WHEN
    let url = format!("{base_url}/api/credential/v1/{}", credential.id);

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

    assert_eq!(resp["id"].as_str().unwrap(), credential.id.to_string());
    assert_eq!(
        resp["schema"]["organisationId"].as_str().unwrap(),
        organisation.id.to_string()
    );
    assert_eq!(resp["schema"]["name"].as_str().unwrap(), "test");
    assert!(resp["revocationDate"].is_null());
    assert_eq!(resp["state"].as_str().unwrap(), "CREATED");
}

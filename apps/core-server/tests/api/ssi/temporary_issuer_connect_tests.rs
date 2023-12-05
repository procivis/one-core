use core_server::router::start_server;
use one_core::model::credential::CredentialStateEnum;
use one_core::model::did::DidType;
use serde_json::{json, Value};

use crate::{fixtures, utils};

#[tokio::test]
async fn test_temporary_issuer_connect_success() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did_web(&db_conn, &organisation, false, DidType::Local).await;
    let credential_schema =
        fixtures::create_credential_schema(&db_conn, "test", &organisation, "NONE").await;
    let credential = fixtures::create_credential(
        &db_conn,
        &credential_schema,
        CredentialStateEnum::Pending,
        &did,
        None,
        None,
        None,
        "PROCIVIS_TEMPORARY",
    )
    .await;

    // WHEN
    let url = format!(
        "{base_url}/ssi/temporary-issuer/v1/connect?protocol=PROCIVIS_TEMPORARY&credential={}",
        credential.id
    );
    let db_cloned = db_conn.clone();
    let _handle = tokio::spawn(async move { start_server(listener, config, db_cloned).await });

    let resp = utils::client()
        .post(url)
        .json(&json!({
          "did": "did:key:test"
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json().await.unwrap();

    assert_eq!(credential.id.to_string(), resp["id"].as_str().unwrap());
    assert_eq!("PENDING", resp["state"].as_str().unwrap());
    assert_eq!(
        credential_schema.id.to_string(),
        resp["schema"]["id"].as_str().unwrap()
    );
    assert_eq!("test", resp["claims"][0]["value"].as_str().unwrap());

    let credential = fixtures::get_credential(&db_conn, &credential.id).await;
    assert_eq!(
        CredentialStateEnum::Offered,
        credential.state.unwrap().first().unwrap().state
    );
}

use core_server::router::start_server;
use one_core::model::credential::CredentialStateEnum;
use serde_json::Value;

use crate::{
    fixtures::{self, TestingCredentialParams},
    utils,
};

#[tokio::test]
async fn test_share_credential_success() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did(&db_conn, &organisation, None).await;
    let credential_schema =
        fixtures::create_credential_schema(&db_conn, "test", &organisation, "NONE").await;
    let credential = fixtures::create_credential(
        &db_conn,
        &credential_schema,
        CredentialStateEnum::Created,
        &did,
        "PROCIVIS_TEMPORARY",
        TestingCredentialParams::default(),
    )
    .await;

    // WHEN
    let url = format!("{base_url}/api/credential/v1/{}/share", credential.id);

    let db_conn_clone = db_conn.clone();
    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn_clone).await });

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json().await.unwrap();

    assert!(resp.get("url").is_some());

    let url = resp["url"].as_str().unwrap();
    assert!(url.ends_with(
        format!(
            "/ssi/temporary-issuer/v1/connect?protocol={}&credential={}",
            "PROCIVIS_TEMPORARY", credential.id
        )
        .as_str()
    ));
    let credential = fixtures::get_credential(&db_conn, &credential.id).await;
    assert_eq!(
        CredentialStateEnum::Pending,
        credential.state.unwrap().first().unwrap().state
    );
}

use core_server::router::start_server;
use one_core::model::credential::CredentialStateEnum;
use serde_json::Value;
use time::OffsetDateTime;

use crate::{
    fixtures::{self, TestingCredentialParams},
    utils::{self, context::TestContext},
};

#[tokio::test]
async fn test_get_list_credential_success() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did(&db_conn, &organisation, None).await;
    let credential_schema =
        fixtures::create_credential_schema(&db_conn, "test", &organisation, "NONE").await;
    for _i in 1..15 {
        fixtures::create_credential(
            &db_conn,
            &credential_schema,
            CredentialStateEnum::Accepted,
            &did,
            "PROCIVIS_TEMPORARY",
            TestingCredentialParams::default(),
        )
        .await;
    }
    // WHEN
    let url = format!(
        "{base_url}/api/credential/v1?page=0&pageSize=8&organisationId={}",
        organisation.id
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
    assert_eq!(resp["values"].as_array().unwrap().len(), 8);
}

#[tokio::test]
async fn test_get_list_credential_deleted_credentials_are_not_returned() {
    // GIVEN
    let context = TestContext::new().await;

    let organisation = context.db.create_organisation().await;
    let did = context.db.create_did(&organisation, None).await;
    let credential_schema = context
        .db
        .create_credential_schema("test", &organisation, "NONE")
        .await;
    for _ in 1..15 {
        context
            .db
            .create_credential(
                &credential_schema,
                CredentialStateEnum::Created,
                &did,
                "PROCIVIS_TEMPORARY",
                TestingCredentialParams::default(),
            )
            .await;
    }

    context
        .db
        .create_credential(
            &credential_schema,
            CredentialStateEnum::Created,
            &did,
            "PROCIVIS_TEMPORARY",
            TestingCredentialParams {
                deleted_at: Some(OffsetDateTime::now_utc()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api_client
        .list_credentials(0, 8, organisation.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalItems"].as_i64().unwrap(), 14);
    assert_eq!(resp["totalPages"].as_i64().unwrap(), 2);
    assert_eq!(resp["values"].as_array().unwrap().len(), 8);
}

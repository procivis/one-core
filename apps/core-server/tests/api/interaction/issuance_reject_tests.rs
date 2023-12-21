use serde_json::json;
use wiremock::{
    http::Method::Post,
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

use core_server::router::start_server;
use one_core::model::credential::CredentialStateEnum;

use crate::{
    fixtures::{self, TestingCredentialParams},
    utils,
};

#[tokio::test]
async fn test_issuance_reject_procivis_temp() {
    // for debugging only
    // _ = tracing_subscriber::fmt().init();
    let mock_server = MockServer::start().await;
    let config = fixtures::create_config(mock_server.uri());
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did(&db_conn, &organisation, None).await;
    let credential_schema =
        fixtures::create_credential_schema(&db_conn, "test", &organisation, "NONE").await;
    let interaction =
        fixtures::create_interaction(&db_conn, &mock_server.uri(), "".as_bytes()).await;
    let credential = fixtures::create_credential(
        &db_conn,
        &credential_schema,
        CredentialStateEnum::Pending,
        &did,
        "PROCIVIS_TEMPORARY",
        TestingCredentialParams {
            interaction: Some(interaction.to_owned()),
            ..Default::default()
        },
    )
    .await;

    Mock::given(method(Post))
        .and(path("/ssi/temporary-issuer/v1/reject"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let url = format!("{base_url}/api/interaction/v1/issuance-reject");

    let backup_db_conn = db_conn.to_owned();

    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn).await });

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "interactionId": interaction.id,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 204);

    let states = fixtures::get_credential(&backup_db_conn, &credential.id)
        .await
        .state
        .unwrap();
    assert_eq!(2, states.len());
    assert_eq!(CredentialStateEnum::Rejected, states[0].state);
}

#[tokio::test]
async fn test_issuance_reject_openid4vc() {
    let mock_server = MockServer::start().await;
    let config = fixtures::create_config(mock_server.uri());
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did(&db_conn, &organisation, None).await;
    let holder_did = fixtures::create_did(&db_conn, &organisation, None).await;

    let credential_schema =
        fixtures::create_credential_schema(&db_conn, "test", &organisation, "NONE").await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/credential", mock_server.uri()),
        "access_token": "123",
        "access_token_expires_at": null,
    }))
    .unwrap();

    let interaction =
        fixtures::create_interaction(&db_conn, &mock_server.uri(), &interaction_data).await;
    let credential = fixtures::create_credential(
        &db_conn,
        &credential_schema,
        CredentialStateEnum::Pending,
        &did,
        "OPENID4VC",
        TestingCredentialParams {
            holder_did: Some(holder_did),
            interaction: Some(interaction.to_owned()),
            ..Default::default()
        },
    )
    .await;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let url = format!("{base_url}/api/interaction/v1/issuance-reject");

    let backup_db_conn = db_conn.to_owned();

    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn).await });

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "interactionId": interaction.id,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 500);

    let states = fixtures::get_credential(&backup_db_conn, &credential.id)
        .await
        .state
        .unwrap();
    assert_eq!(1, states.len());
    assert_eq!(CredentialStateEnum::Pending, states[0].state);
}

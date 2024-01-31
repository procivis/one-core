use serde_json::json;
use wiremock::{
    http::Method::Post,
    matchers::{method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

use core_server::router::start_server;
use one_core::model::{
    credential::CredentialStateEnum,
    did::{DidType, KeyRole, RelatedKey},
};

use crate::{
    fixtures::{self, TestingCredentialParams, TestingDidParams},
    utils,
};

#[tokio::test]
async fn test_issuance_accept_procivis_temp() {
    // for debugging only
    // _ = tracing_subscriber::fmt().init();
    let mock_server = MockServer::start().await;
    let config = fixtures::create_config(mock_server.uri(), None);
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
        .and(path("/ssi/temporary-issuer/v1/submit"))
        .and(query_param("credentialId", credential.id.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "credential": "123",
            "format": "JWT"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let url = format!("{base_url}/api/interaction/v1/issuance-accept");

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
    assert_eq!(CredentialStateEnum::Accepted, states[0].state);
}

#[tokio::test]
async fn test_issuance_accept_openid4vc() {
    // for debugging only
    // _ = tracing_subscriber::fmt().init();
    let mock_server = MockServer::start().await;
    let config = fixtures::create_config(mock_server.uri(), None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let issuer_did = fixtures::create_did(
        &db_conn,
        &organisation,
        Some(TestingDidParams {
            did_type: Some(DidType::Remote),
            ..Default::default()
        }),
    )
    .await;
    let key = fixtures::create_es256_key(&db_conn, &organisation).await;
    let holder_did = fixtures::create_did(
        &db_conn,
        &organisation,
        Some(TestingDidParams {
            keys: Some(vec![RelatedKey {
                role: KeyRole::Authentication,
                key,
            }]),
            ..Default::default()
        }),
    )
    .await;

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
        &issuer_did,
        "OPENID4VC",
        TestingCredentialParams {
            holder_did: Some(holder_did),
            interaction: Some(interaction.to_owned()),
            ..Default::default()
        },
    )
    .await;

    Mock::given(method(Post))
        .and(path("/credential"))
        //.and(query_param("credentialId", credential.id.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "credential": "eyJhbGciOiJFRERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MDEyNTk2MzcsImV4cCI6MTc2NDMzMTYzNywibmJmIjoxNzAxMjU5NTc3LCJpc3MiOiJkaWQ6a2V5Ono2TWt2M0hMNTJYSk5oNHJkdG5QS1BSbmRHd1U4bkF1VnBFN3lGRmllNVNOeFprWCIsInN1YiI6ImRkMmZmMDE2LTVmYmUtNDNiMC1hMmJhLTNiMDIzZWNjNTRmYiIsImp0aSI6IjNjNDgwYjUxLTI0ZDQtNGM3OS05MDViLTI3MTQ4YjYyY2RlNiIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93M2lkLm9yZy92Yy9zdGF0dXMtbGlzdC8yMDIxL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsic3RyaW5nIjoic3RyaW5nIn0sImNyZWRlbnRpYWxTdGF0dXMiOnsiaWQiOiJodHRwOi8vMC4wLjAuMDozMDAwL3NzaS9yZXZvY2F0aW9uL3YxL2xpc3QvOGJmNmRjOGYtMjI4Zi00MTVjLTgzZjItOTVkODUxYzE5MjdiIzAiLCJ0eXBlIjoiU3RhdHVzTGlzdDIwMjFFbnRyeSIsInN0YXR1c1B1cnBvc2UiOiJyZXZvY2F0aW9uIiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwOi8vMC4wLjAuMDozMDAwL3NzaS9yZXZvY2F0aW9uL3YxL2xpc3QvOGJmNmRjOGYtMjI4Zi00MTVjLTgzZjItOTVkODUxYzE5MjdiIiwic3RhdHVzTGlzdEluZGV4IjoiMCJ9fX0.JUe1lljvJAXMMLr9mKOKLMFJ1XQr_GzL0i8JTOvt1_uNwVgQzMFQPqMUZ-sQg2JtWogDHLaUsjW64yFyc7ExCg",
            "format": "JWT"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let url = format!("{base_url}/api/interaction/v1/issuance-accept");

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
    assert_eq!(CredentialStateEnum::Accepted, states[0].state);
}

use core_server::router::start_server;
use one_core::model::credential::CredentialStateEnum;
use one_core::model::did::KeyRole;
use uuid::Uuid;

use crate::{fixtures, utils};

#[tokio::test]
async fn test_revoke_credential_success() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did_key(&db_conn, &organisation).await;
    let key = fixtures::create_eddsa_key(
        &db_conn,
        "EDDSA".to_string(),
        &organisation.id.to_string(),
        &did.id,
    )
    .await;
    fixtures::create_key_did(
        &db_conn,
        &did.id.to_string(),
        &key,
        KeyRole::AssertionMethod,
    )
    .await;
    let credential_schema =
        fixtures::create_credential_schema(&db_conn, "test", &organisation, "STATUSLIST2021").await;
    let credential = fixtures::create_credential(
        &db_conn,
        &credential_schema,
        CredentialStateEnum::Accepted,
        &did,
        None,
        "PROCIVIS_TEMPORARY",
    )
    .await;

    fixtures::create_revocation_list(&db_conn, &did).await;
    // WHEN
    let url = format!("{base_url}/api/credential/v1/{}/revoke", credential.id);

    let db_conn_clone = db_conn.clone();
    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn_clone).await });

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 204);

    let credential = fixtures::get_credential(&db_conn, &credential.id).await;
    assert_eq!(
        CredentialStateEnum::Revoked,
        credential.state.unwrap().first().unwrap().state
    );
}

#[tokio::test]
async fn test_revoke_credential_not_found() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;

    // WHEN
    let url = format!("{base_url}/api/credential/v1/{}/revoke", Uuid::new_v4());

    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn).await });

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 404);
}

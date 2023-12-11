use core_server::router::start_server;
use one_core::model::credential::CredentialStateEnum;
use one_core::model::did::{DidType, KeyRole, RelatedKey};
use serde_json::Value;

use crate::fixtures::TestingDidParams;
use crate::{fixtures, utils};

#[tokio::test]
async fn test_temporary_issuer_submit_success() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let key = fixtures::create_eddsa_key(&db_conn, &organisation).await;
    let issuer_did = fixtures::create_did(
        &db_conn,
        &organisation,
        Some(TestingDidParams {
            keys: Some(vec![RelatedKey {
                role: KeyRole::AssertionMethod,
                key,
            }]),
            ..Default::default()
        }),
    )
    .await;

    let holder_did = fixtures::create_did(
        &db_conn,
        &organisation,
        Some(TestingDidParams {
            did_type: Some(DidType::Remote),
            ..Default::default()
        }),
    )
    .await;
    let credential_schema =
        fixtures::create_credential_schema(&db_conn, "test", &organisation, "NONE").await;
    let credential = fixtures::create_credential(
        &db_conn,
        &credential_schema,
        CredentialStateEnum::Offered,
        &issuer_did,
        Some(holder_did),
        None,
        None,
        "PROCIVIS_TEMPORARY",
    )
    .await;

    // WHEN
    let url = format!(
        "{base_url}/ssi/temporary-issuer/v1/submit?credentialId={}",
        credential.id
    );
    let db_cloned = db_conn.clone();
    let _handle = tokio::spawn(async move { start_server(listener, config, db_cloned).await });

    let resp = utils::client().post(url).send().await.unwrap();

    // THEN
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json().await.unwrap();

    assert_eq!("JWT", resp["format"].as_str().unwrap());
    assert!(!resp["credential"].as_str().unwrap().is_empty());

    let credential = fixtures::get_credential(&db_conn, &credential.id).await;
    assert_eq!(
        CredentialStateEnum::Accepted,
        credential.state.unwrap().first().unwrap().state
    );
}

use one_core::model::{
    credential::CredentialStateEnum,
    did::{DidType, KeyRole, RelatedKey},
};
use serde_json::Value;

use crate::{fixtures::TestingCredentialParams, utils::server::run_server};
use crate::{
    fixtures::{self, TestingDidParams},
    utils,
};

#[tokio::test]
async fn test_add_credential_to_list() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let key = fixtures::create_eddsa_key(&db_conn, &organisation).await;
    let issuer_did = fixtures::create_did(
        &db_conn,
        &organisation,
        Some(TestingDidParams {
            keys: Some(vec![RelatedKey {
                role: KeyRole::AssertionMethod,
                key: key.to_owned(),
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
        fixtures::create_credential_schema(&db_conn, "test", &organisation, "BITSTRINGSTATUSLIST")
            .await;
    let credential = fixtures::create_credential(
        &db_conn,
        &credential_schema,
        CredentialStateEnum::Offered,
        &issuer_did,
        "PROCIVIS_TEMPORARY",
        TestingCredentialParams {
            holder_did: Some(holder_did.clone()),
            key: Some(key),
            ..Default::default()
        },
    )
    .await;

    // WHEN
    let _handle = run_server(listener, config, &db_conn);

    let url = format!(
        "{base_url}/ssi/temporary-issuer/v1/submit?credentialId={}&didId={}",
        credential.id, holder_did.id
    );

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

    // Such a list is created in the flow
    assert!(fixtures::get_revocation_list(&db_conn, &issuer_did)
        .await
        .is_ok());
}

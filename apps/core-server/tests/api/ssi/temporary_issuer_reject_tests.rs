use one_core::model::credential::CredentialStateEnum;
use one_core::model::did::DidType;

use crate::{
    fixtures::{self, TestingCredentialParams, TestingDidParams},
    utils::{self, server::run_server},
};

#[tokio::test]
async fn test_temporary_issuer_reject_success() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let issuer_did = fixtures::create_did(&db_conn, &organisation, None).await;
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
        "PROCIVIS_TEMPORARY",
        TestingCredentialParams {
            holder_did: Some(holder_did),
            ..Default::default()
        },
    )
    .await;

    // WHEN
    let _handle = run_server(listener, config, &db_conn);
    let url = format!(
        "{base_url}/ssi/temporary-issuer/v1/reject?credentialId={}",
        credential.id
    );

    let resp = utils::client().post(url).send().await.unwrap();

    // THEN
    assert_eq!(resp.status(), 204);

    let credential = fixtures::get_credential(&db_conn, &credential.id).await;
    assert_eq!(
        CredentialStateEnum::Rejected,
        credential.state.unwrap().first().unwrap().state
    );
}

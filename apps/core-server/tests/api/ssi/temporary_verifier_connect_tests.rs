use core_server::router::start_server;
use one_core::model::did::DidType;
use one_core::model::proof::ProofStateEnum;
use serde_json::{json, Value};
use validator::HasLen;

use crate::{
    fixtures::{self, TestingDidParams},
    utils,
};

#[tokio::test]
async fn test_temporary_verifier_connect_success() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did(&db_conn, &organisation, None).await;
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
    let claim_schema = credential_schema
        .claim_schemas
        .unwrap()
        .first()
        .unwrap()
        .schema
        .to_owned();

    let proof_schema = fixtures::create_proof_schema(
        &db_conn,
        "test",
        &organisation,
        &[(
            claim_schema.id,
            &claim_schema.key,
            true,
            &claim_schema.data_type,
        )],
    )
    .await;

    let proof = fixtures::create_proof(
        &db_conn,
        &did,
        None,
        Some(&proof_schema),
        ProofStateEnum::Pending,
        "OPENID4VC",
        None,
    )
    .await;

    // WHEN
    let url = format!(
        "{base_url}/ssi/temporary-verifier/v1/connect?protocol=PROCIVIS_TEMPORARY&proof={}",
        proof.id
    );
    let db_cloned = db_conn.clone();
    let _handle = tokio::spawn(async move { start_server(listener, config, db_cloned).await });

    let resp = utils::client()
        .post(url)
        .json(&json!({
          "did": holder_did.did
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json().await.unwrap();

    assert_eq!(did.did.to_string(), resp["verifierDid"].as_str().unwrap());
    assert_eq!(1, resp["claims"].as_array().unwrap().length());

    let proof = fixtures::get_proof(&db_conn, &proof.id).await;
    assert_eq!(
        ProofStateEnum::Offered,
        proof.state.unwrap().first().unwrap().state
    );
}

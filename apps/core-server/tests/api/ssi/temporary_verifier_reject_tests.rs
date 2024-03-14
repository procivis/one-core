use one_core::model::proof::ProofStateEnum;

use crate::{
    fixtures,
    utils::{self, server::run_server},
};

#[tokio::test]
async fn test_temporary_verifier_reject_success() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did(&db_conn, &organisation, None).await;

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
        ProofStateEnum::Requested,
        "OPENID4VC",
        None,
    )
    .await;

    // WHEN
    let _handle = run_server(listener, config, &db_conn);
    let url = format!(
        "{base_url}/ssi/temporary-verifier/v1/reject?proof={}&didId={}",
        proof.id, did.id
    );

    let resp = utils::client().post(url).send().await.unwrap();

    // THEN
    assert_eq!(resp.status(), 204);

    let proof = fixtures::get_proof(&db_conn, &proof.id).await;
    assert_eq!(
        ProofStateEnum::Rejected,
        proof.state.unwrap().first().unwrap().state
    );
}

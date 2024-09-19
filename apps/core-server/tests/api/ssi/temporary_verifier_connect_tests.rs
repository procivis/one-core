use one_core::model::proof::ProofStateEnum;
use serde_json::Value;

use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};
use crate::utils::server::run_server;
use crate::{fixtures, utils};

#[tokio::test]
async fn test_temporary_verifier_connect_success() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did(&db_conn, &organisation, None).await;

    let credential_schema = fixtures::create_credential_schema(&db_conn, &organisation, None).await;
    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .first()
        .unwrap()
        .schema
        .to_owned();

    let proof_schema = fixtures::create_proof_schema(
        &db_conn,
        "test",
        &organisation,
        &[CreateProofInputSchema {
            claims: vec![CreateProofClaim {
                id: claim_schema.id,
                key: &claim_schema.key,
                required: true,
                data_type: &claim_schema.data_type,
                array: false,
            }],
            credential_schema: &credential_schema,
            validity_constraint: None,
        }],
    )
    .await;

    let proof = fixtures::create_proof(
        &db_conn,
        &did,
        None,
        Some(&proof_schema),
        ProofStateEnum::Pending,
        "PROCIVIS_TEMPORARY",
        None,
    )
    .await;

    // WHEN
    let _handle = run_server(listener, config, &db_conn);
    let url = format!(
        "{base_url}/ssi/temporary-verifier/v1/connect?protocol=PROCIVIS_TEMPORARY&proof={}",
        proof.id
    );

    let resp = utils::client().post(url).send().await.unwrap();

    // THEN
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json().await.unwrap();

    assert_eq!(did.did.to_string(), resp["verifierDid"].as_str().unwrap());
    assert_eq!(1, resp["claims"].as_array().unwrap().len());

    let proof = fixtures::get_proof(&db_conn, &proof.id).await;
    assert_eq!(
        ProofStateEnum::Requested,
        proof.state.unwrap().first().unwrap().state
    );
}

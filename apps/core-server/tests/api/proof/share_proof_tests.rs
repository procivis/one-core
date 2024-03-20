use one_core::model::proof::ProofStateEnum;
use serde_json::Value;

use crate::{
    fixtures,
    utils::{
        self,
        db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema},
        server::run_server,
    },
};

#[tokio::test]
async fn test_share_proof_success() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;

    let organisation = fixtures::create_organisation(&db_conn).await;

    let credential_schema =
        fixtures::create_credential_schema(&db_conn, "test", &organisation, "NONE").await;
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
            }],
            credential_schema: &credential_schema,
            validity_constraint: None,
        }],
    )
    .await;

    let did = fixtures::create_did(&db_conn, &organisation, None).await;

    let proof = fixtures::create_proof(
        &db_conn,
        &did,
        None,
        Some(&proof_schema),
        ProofStateEnum::Created,
        "PROCIVIS_TEMPORARY",
        None,
    )
    .await;

    // WHEN
    let _handle = run_server(listener, config, &db_conn);

    let url = format!("{base_url}/api/proof-request/v1/{}/share", proof.id);
    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json().await.unwrap();
    let url = resp["url"].as_str().unwrap();
    assert!(url.ends_with(&format!(
        "/ssi/temporary-verifier/v1/connect?protocol={}&proof={}",
        "PROCIVIS_TEMPORARY", proof.id
    )));
}

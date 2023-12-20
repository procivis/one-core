use std::str::FromStr;

use core_server::router::start_server;
use one_core::model::proof::ProofStateEnum;
use shared_types::DidValue;
use uuid::Uuid;

use crate::{
    fixtures::{self, TestingDidParams},
    utils,
};

static PRESENTATION_TOKEN: &str = "eyJhbGciOiJFRERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MDAxNDQ0MjMsImV4cCI6MzMyMzYxNDQ0MjMsIm5iZiI6MTcwMDE\
0NDM2MywiaXNzIjoiZGlkOmtleTp6Nk1rdHRpSlZaQjRkd1drRjlBTHdhRUxVRHE1Smo5ajFCaFpITnpOY0xWTmFtNm4iLCJzdWIiOiJkaWQ6a2V5Ono2TWt\
0dGlKVlpCNGR3V2tGOUFMd2FFTFVEcTVKajlqMUJoWkhOek5jTFZOYW02biIsImp0aSI6IjA5NzUyNTRkLWUwZGYtNGM1Ny04MmEzLTFmOGVlNzg3ODAxNCI\
sIm5vbmNlIjoibm9uY2UxMjMiLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZ\
lcmlmaWFibGVQcmVzZW50YXRpb24iXSwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlsiZXlKaGJHY2lPaUpGUkVSVFFTSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnB\
ZWFFpT2pFM01EQXhORFF4T1RFc0ltVjRjQ0k2TVRjMk16SXhOakU1TVN3aWJtSm1Jam94TnpBd01UUTBNVE14TENKcGMzTWlPaUprYVdRNmEyVjVPbm8yVFd\
0MWQwRjFSalZxTmtFNWJYZFdVM3BwUkdvek5XdHhSRkZaYlhwYU9USnhZV2c1VFhkUVMzRnlSbFppV1NJc0luTjFZaUk2SW1ScFpEcHJaWGs2ZWpaTmEzUjB\
hVXBXV2tJMFpIZFhhMFk1UVV4M1lVVk1WVVJ4TlVwcU9Xb3hRbWhhU0U1NlRtTk1WazVoYlRadUlpd2lhblJwSWpvaVl6QXlOVFJoWmpndE5UbGpNeTAwTWp\
ZekxXRXlPRGt0TldaaFkyUTFNell3TlRrMklpd2lkbU1pT25zaVFHTnZiblJsZUhRaU9sc2lhSFIwY0hNNkx5OTNkM2N1ZHpNdWIzSm5Mekl3TVRndlkzSmx\
aR1Z1ZEdsaGJITXZkakVpWFN3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSmRMQ0pqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ0k2ZXl\
KallYUXhJam9pUTBGVU1TSjlmWDAuZEF3UFJSQkQwMUh4cVlVd0pOMHlhVmJ4Si1JanctRURQUXhMOW5oRTYwREZHaFVHNUlhUDhqN0dBYW0xMlJCYi0zSnd\
vOFJHUHJrN3A0Y0diNFdOQlEiXX19.uD-PTubYXem7PtYT0R7KsSNvMDLQgHMRHGPUqZdZExg2c3-ygeD-xHszC6N1ZzVlAvOxmEduf6RQjxPZ9OJWBg";

#[tokio::test]
async fn test_correct() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;

    let new_claim_schemas: Vec<(Uuid, &str, bool, &str)> = vec![
        (Uuid::new_v4(), "cat1", true, "STRING"), // Presentation 1 token 1
        (Uuid::new_v4(), "cat2", false, "STRING"), // Optional - not provided
    ];

    fixtures::create_credential_schema_with_claims(
        &db_conn,
        "NewCredentialSchema",
        &organisation,
        "NONE",
        &new_claim_schemas,
    )
    .await;

    let proof_schema =
        fixtures::create_proof_schema(&db_conn, "Schema1", &organisation, &new_claim_schemas).await;

    let verifier_did = fixtures::create_did(&db_conn, &organisation, None).await;
    let holder_did = fixtures::create_did(
        &db_conn,
        &organisation,
        Some(TestingDidParams {
            did: Some(
                DidValue::from_str("did:key:z6MkttiJVZB4dwWkF9ALwaELUDq5Jj9j1BhZHNzNcLVNam6n")
                    .unwrap(),
            ),
            ..Default::default()
        }),
    )
    .await;

    let interaction = fixtures::create_interaction(&db_conn, &base_url, "123".as_bytes()).await;

    let proof = fixtures::create_proof(
        &db_conn,
        &verifier_did,
        Some(&holder_did),
        Some(&proof_schema),
        ProofStateEnum::Offered,
        "PROCIVIS_TEMPORARY",
        Some(&interaction),
    )
    .await;

    // WHEN
    let db_conn_moved = db_conn.clone();
    let _handle =
        tokio::spawn(async move { start_server(listener, config, db_conn_moved.clone()).await });

    let url = format!("{base_url}/ssi/temporary-verifier/v1/submit");

    let params = [("proof", proof.id)];

    let resp = utils::client()
        .post(url)
        .body(PRESENTATION_TOKEN)
        .query(&params)
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 204);

    let proof = fixtures::get_proof(&db_conn, &proof.id).await;
    assert_eq!(
        proof.state.unwrap().first().unwrap().state,
        ProofStateEnum::Accepted
    );

    let claims = proof.claims.unwrap();
    assert!(new_claim_schemas
        .iter()
        .filter(|required_claim| required_claim.2) //required
        .all(|required_claim| claims
            .iter()
            // Values are just keys uppercase
            .any(|db_claim| db_claim.value == required_claim.1.to_ascii_uppercase())));
}

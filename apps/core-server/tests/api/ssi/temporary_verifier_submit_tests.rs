use std::str::FromStr;

use one_core::model::proof::ProofStateEnum;
use shared_types::DidValue;
use uuid::Uuid;

use crate::{
    fixtures::{self, TestingDidParams},
    utils::{self, server::run_server},
};

static PRESENTATION_TOKEN: &str = "eyJhbGciOiJFRERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MDAxMzgwNTcsImV4cCI6MzMyMzYxMzgwNTcsIm5iZiI6MTcwMDEz\
Nzk5NywiaXNzIjoiZGlkOmtleTp6Nk1rdHRpSlZaQjRkd1drRjlBTHdhRUxVRHE1Smo5ajFCaFpITnpOY0xWTmFtNm4iLCJzdWIiOiJkaWQ6a2V5Ono2TWt0\
dGlKVlpCNGR3V2tGOUFMd2FFTFVEcTVKajlqMUJoWkhOek5jTFZOYW02biIsImp0aSI6ImEwYmVhNmI3LWYwMjQtNGZiZS05MDNiLWM1MGFmYzhhYjE4ZCIs\
Im5vbmNlIjoibm9uY2UxMjMiLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZl\
cmlmaWFibGVQcmVzZW50YXRpb24iXSwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlsiZXlKaGJHY2lPaUpGUkVSVFFTSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnBZ\
WFFpT2pFM01EQXdOVEF3TURRc0ltVjRjQ0k2TVRjMk16RXlNakF3TkN3aWJtSm1Jam94TnpBd01EUTVPVFEwTENKcGMzTWlPaUprYVdRNmEyVjVPbm8yVFd0\
MWQwRjFSalZxTmtFNWJYZFdVM3BwUkdvek5XdHhSRkZaYlhwYU9USnhZV2c1VFhkUVMzRnlSbFppV1NJc0luTjFZaUk2SW1ScFpEcHJaWGs2ZWpaTmEzUjBh\
VXBXV2tJMFpIZFhhMFk1UVV4M1lVVk1WVVJ4TlVwcU9Xb3hRbWhhU0U1NlRtTk1WazVoYlRadUlpd2lhblJwSWpvaU5HWmtZVEkyWldJdFpUWmxOaTAwTm1Z\
MExUZzVOVEV0WXpKa09EaGpNRGRpTjJFMUlpd2lkbU1pT25zaVFHTnZiblJsZUhRaU9sc2lhSFIwY0hNNkx5OTNkM2N1ZHpNdWIzSm5Mekl3TVRndlkzSmxa\
R1Z1ZEdsaGJITXZkakVpWFN3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSmRMQ0pqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ0k2ZXlK\
d1pYUXhJam9pVUVWVU1TSXNJbkJsZERJaU9pSlFSVlF5SW4xOWZRLkRuYXVBOUQ2dk8tQXpFZ0pmTUJiMXhKRUU4b2loN1I5WWpSWG1hRDMyVXU2LXFQSU80\
bXA0N3Zaa1puQjl6N0VmcV9uMUFyNWo3N0JBVlVrOU5XcERnIiwiZXlKaGJHY2lPaUpGUkVSVFFTSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnBZWFFpT2pFM01E\
QXdORGs0TmpVc0ltVjRjQ0k2TVRjMk16RXlNVGcyTlN3aWJtSm1Jam94TnpBd01EUTVPREExTENKcGMzTWlPaUprYVdRNmEyVjVPbm8yVFd0MWQwRjFSalZx\
TmtFNWJYZFdVM3BwUkdvek5XdHhSRkZaYlhwYU9USnhZV2c1VFhkUVMzRnlSbFppV1NJc0luTjFZaUk2SW1ScFpEcHJaWGs2ZWpaTmEzUjBhVXBXV2tJMFpI\
ZFhhMFk1UVV4M1lVVk1WVVJ4TlVwcU9Xb3hRbWhhU0U1NlRtTk1WazVoYlRadUlpd2lhblJwSWpvaVlUZGhZMlprWm1RdE5EUmtZaTAwTXpJMUxUZzBOR0V0\
TURFNE9UYzRObVEzWkRkaElpd2lkbU1pT25zaVFHTnZiblJsZUhRaU9sc2lhSFIwY0hNNkx5OTNkM2N1ZHpNdWIzSm5Mekl3TVRndlkzSmxaR1Z1ZEdsaGJI\
TXZkakVpWFN3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSmRMQ0pqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ0k2ZXlKdVlXMWxNaUk2\
SWs1QlRVVXlJaXdpYm1GdFpURWlPaUpPUVUxRk1TSjlmWDAuMUoyNmNjOFVTSHNISlAwX01iWHMzUzlLalRvWUdCMTZUekd0a1lyRWN1SXhaaVFTd1FzWnJM\
MFd1Y1dPVm9NbDZjQjFmNFN3SF9pUmt6bFU1TjYyQVEiXX19.JJqURzZQGeeJMP9iI2IwIqYzgb_e1d6_lWVO8-G-lqq3yudM-Q5y1toOpduyD8acxrIhE7J\
PX3vs6mhX2DmXDQ";

#[tokio::test]
async fn test_correct() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;

    let new_claim_schemas_credential_1: Vec<(Uuid, &str, bool, &str)> = vec![
        (Uuid::new_v4(), "pet1", true, "STRING"),
        (Uuid::new_v4(), "pet2", true, "STRING"),
        (Uuid::new_v4(), "pet3", false, "STRING"), // Optional, not provided in credentials
    ];

    fixtures::create_credential_schema_with_claims(
        &db_conn,
        "NewCredentialSchema",
        &organisation,
        "NONE",
        &new_claim_schemas_credential_1,
    )
    .await;

    let new_claim_schemas_credential_2: Vec<(Uuid, &str, bool, &str)> = vec![
        (Uuid::new_v4(), "name1", true, "STRING"),
        (Uuid::new_v4(), "name2", true, "STRING"),
    ];

    fixtures::create_credential_schema_with_claims(
        &db_conn,
        "NewCredentialSchema2",
        &organisation,
        "NONE",
        &new_claim_schemas_credential_2,
    )
    .await;

    let new_claim_schemas_proof: Vec<(Uuid, &str, bool, &str)> = vec![
        new_claim_schemas_credential_1[1], // Token 1
        new_claim_schemas_credential_1[2], // Optional, not provided in presentation
        new_claim_schemas_credential_2[0], // Token 2
    ];

    let proof_schema =
        fixtures::create_proof_schema(&db_conn, "Schema1", &organisation, &new_claim_schemas_proof)
            .await;

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
        ProofStateEnum::Requested,
        "PROCIVIS_TEMPORARY",
        Some(&interaction),
    )
    .await;

    // WHEN
    let _handle = run_server(listener, config, &db_conn);

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
    assert!(new_claim_schemas_proof
        .iter()
        .filter(|required_claim| required_claim.2) //required
        .all(|required_claim| claims
            .iter()
            // Values are just keys uppercase
            .any(|db_claim| db_claim.claim.value == required_claim.1.to_ascii_uppercase())));
}

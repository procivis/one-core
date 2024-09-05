use std::collections::BTreeSet;

use one_core::model::proof::ProofStateEnum;
use uuid::Uuid;

use crate::fixtures;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};
use crate::utils::server::run_server;
use crate::utils::{self};

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

    let new_claim_schemas_credential_1: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (Uuid::new_v4(), "pet1", true, "STRING", false),
        (Uuid::new_v4(), "pet2", true, "STRING", false),
        (Uuid::new_v4(), "pet3", false, "STRING", false), // Optional, not provided in credentials
    ];

    let credential_schema1 = fixtures::create_credential_schema_with_claims(
        &db_conn,
        "NewCredentialSchema",
        &organisation,
        "NONE",
        &new_claim_schemas_credential_1,
    )
    .await;

    let new_claim_schemas_credential_2: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (Uuid::new_v4(), "name1", true, "STRING", false),
        (Uuid::new_v4(), "name2", true, "STRING", false),
    ];

    let credential_schema2 = fixtures::create_credential_schema_with_claims(
        &db_conn,
        "NewCredentialSchema2",
        &organisation,
        "NONE",
        &new_claim_schemas_credential_2,
    )
    .await;

    let proof_input_schemas = [
        CreateProofInputSchema {
            claims: vec![
                CreateProofClaim::from(&new_claim_schemas_credential_1[1]),
                CreateProofClaim::from(&new_claim_schemas_credential_1[2]),
            ],
            credential_schema: &credential_schema1,
            validity_constraint: None,
        },
        CreateProofInputSchema {
            claims: vec![CreateProofClaim::from(&new_claim_schemas_credential_2[0])], // Token 2
            credential_schema: &credential_schema2,
            validity_constraint: None,
        },
    ];

    let proof_schema =
        fixtures::create_proof_schema(&db_conn, "Schema1", &organisation, &proof_input_schemas)
            .await;

    let verifier_did = fixtures::create_did(&db_conn, &organisation, None).await;
    let holder_did = "did:key:z6MkttiJVZB4dwWkF9ALwaELUDq5Jj9j1BhZHNzNcLVNam6n";

    let interaction = fixtures::create_interaction(&db_conn, &base_url, "123".as_bytes()).await;

    let proof = fixtures::create_proof(
        &db_conn,
        &verifier_did,
        None,
        Some(&proof_schema),
        ProofStateEnum::Requested,
        "PROCIVIS_TEMPORARY",
        Some(&interaction),
    )
    .await;

    // WHEN
    let _handle = run_server(listener, config, &db_conn);

    let url = format!("{base_url}/ssi/temporary-verifier/v1/submit");

    let params = [
        ("proof", proof.id.to_string()),
        ("didValue", holder_did.to_string()),
    ];

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

    let claims: BTreeSet<String> = proof
        .claims
        .unwrap()
        .into_iter()
        .map(|c| c.claim.value)
        .collect();
    let expected_claims: BTreeSet<String> = proof_input_schemas
        .into_iter()
        .flat_map(|c| c.claims)
        .filter_map(|c| c.required.then_some(c.key.to_ascii_uppercase()))
        .collect();

    assert_eq!(expected_claims, claims);
}

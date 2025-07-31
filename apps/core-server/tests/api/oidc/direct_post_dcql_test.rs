use one_core::model::proof::{ProofRole, ProofStateEnum};
use serde_json::json;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::{
    self, create_credential_schema_with_claims, create_proof, create_proof_schema, get_proof,
};
use crate::utils;
use crate::utils::context::TestContext;
use crate::utils::db_clients::proof_schemas::CreateProofInputSchema;

static TOKEN2: &str = "eyJhbGciOiJFRERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MDAxNDQ0MjMsImV4cCI6MzMyMzYxNDQ0MjMsIm5iZiI6MTcwMDE\
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
async fn test_direct_post_draft25_with_dcql_query() {
    // GIVEN
    let (context, organisation, _, verifier_identifier, verifier_key) =
        TestContext::new_with_did(None).await;
    let nonce = "nonce123";

    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (Uuid::new_v4(), "cat1", true, "STRING", false), // Required claim
        (Uuid::new_v4(), "cat2", false, "STRING", false), // Optional claim - not provided
    ];

    let credential_schema = create_credential_schema_with_claims(
        &context.db.db_conn,
        "NewCredentialSchema",
        &organisation,
        "NONE",
        &new_claim_schemas,
    )
    .await;

    let proof_schema = create_proof_schema(
        &context.db.db_conn,
        "Schema1",
        &organisation,
        &[CreateProofInputSchema::from((
            &new_claim_schemas[..],
            &credential_schema,
        ))],
    )
    .await;

    // Create DCQL query instead of presentation definition
    let dcql_query = json!({
        "credentials": [{
            "id": credential_schema.id.to_string(),
            "format": "jwt_vc_json",
            "meta": {
                "type_values": [[
                    "https://www.w3.org/2018/credentials#VerifiableCredential",
                    format!("{}#{}", credential_schema.schema_id, "NewCredentialSchema")
                ]]
            },
            "claims": [
                {
                    "id": new_claim_schemas[0].0.to_string(),
                    "path": ["credentialSubject", "cat1"],
                    "required": true
                },
                {
                    "id": new_claim_schemas[1].0.to_string(),
                    "path": ["credentialSubject", "cat2"],
                    "required": false
                }
            ],
            "claim_sets": [
                [
                    new_claim_schemas[0].0.to_string(),
                    new_claim_schemas[1].0.to_string()
                ],
                [
                    new_claim_schemas[0].0.to_string()
                ]
            ]
        }]
    });

    let interaction_data = json!({
        "nonce": nonce,
        "dcql_query": dcql_query,
        "client_id": "client_id",
        "client_id_scheme": "redirect_uri",
        "response_uri": "response_uri"
    });

    let base_url = context.config.app.core_base_url.clone();
    let interaction = fixtures::create_interaction(
        &context.db.db_conn,
        &base_url,
        interaction_data.to_string().as_bytes(),
        &organisation,
    )
    .await;

    let proof = create_proof(
        &context.db.db_conn,
        &verifier_identifier,
        None,
        Some(&proof_schema),
        ProofStateEnum::Pending,
        ProofRole::Verifier,
        "OPENID4VP_DRAFT25",
        Some(&interaction),
        Some(&verifier_key),
        None,
    )
    .await;

    // For DCQL, vp_token is a HashMap<String, Vec<String>> sent as JSON string
    let vp_token_map = json!({
        credential_schema.id.to_string(): [TOKEN2]
    });

    let params = [
        ("vp_token", vp_token_map.to_string()),
        ("state", interaction.id.to_string()),
    ];

    // WHEN
    let url = format!("{base_url}/ssi/openid4vp/draft-25/response");
    let resp = utils::client()
        .post(url)
        .form(&params)
        .send()
        .await
        .unwrap();

    // THEN
    // Note: This test may fail until DCQL processing is fully implemented
    // (the service method currently has a todo!())
    assert_eq!(resp.status(), 200);

    let proof = get_proof(&context.db.db_conn, &proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Accepted);

    let proof_history = context
        .db
        .histories
        .get_by_entity_id(&proof.id.into())
        .await;
    assert_eq!(
        proof_history
            .values
            .first()
            .as_ref()
            .unwrap()
            .target
            .as_ref()
            .unwrap(),
        &proof.holder_identifier.unwrap().id.to_string()
    );

    let claims = proof.claims.unwrap();
    assert!(
        claims
            .first()
            .as_ref()
            .unwrap()
            .credential
            .as_ref()
            .unwrap()
            .issuance_date
            .is_some()
    );
    assert!(
        new_claim_schemas
            .iter()
            .filter(|required_claim| required_claim.2) //required
            .all(|required_claim| claims
                .iter()
                // Values are just keys uppercase
                .any(|db_claim| db_claim.claim.value == required_claim.1.to_ascii_uppercase()))
    );
}

#[tokio::test]
async fn test_direct_post_dcql_one_credential_missing_required_claim() {
    // GIVEN
    let (context, organisation, _, verifier_identifier, verifier_key) =
        TestContext::new_with_did(None).await;
    let nonce = "nonce123";

    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (Uuid::new_v4(), "cat1", true, "STRING", false), // Required claim
        (Uuid::new_v4(), "cat2", true, "STRING", false), // Required - not provided
    ];

    let credential_schema = create_credential_schema_with_claims(
        &context.db.db_conn,
        "NewCredentialSchema",
        &organisation,
        "NONE",
        &new_claim_schemas,
    )
    .await;

    let proof_schema = create_proof_schema(
        &context.db.db_conn,
        "Schema1",
        &organisation,
        &[CreateProofInputSchema::from((
            &new_claim_schemas[..],
            &credential_schema,
        ))],
    )
    .await;

    // Create DCQL query with both required claims
    let dcql_query = json!({
        "credentials": [{
            "id": credential_schema.id.to_string(),
            "format": "jwt_vc_json",
            "meta": {
                "type_values": [[
                    "https://www.w3.org/2018/credentials#VerifiableCredential",
                    format!("{}#{}", credential_schema.schema_id, "NewCredentialSchema")
                ]]
            },
            "claims": [
                {
                    "id": new_claim_schemas[0].0.to_string(),
                    "path": ["credentialSubject", "cat1"],
                    "required": true
                },
                {
                    "id": new_claim_schemas[1].0.to_string(),
                    "path": ["credentialSubject", "cat2"],
                    "required": true
                }
            ]
        }]
    });

    let interaction_data = json!({
        "nonce": nonce,
        "dcql_query": dcql_query,
        "client_id": "client_id",
        "client_id_scheme": "redirect_uri",
        "response_uri": "response_uri"
    });

    let base_url = context.config.app.core_base_url.clone();
    let interaction = fixtures::create_interaction(
        &context.db.db_conn,
        &base_url,
        interaction_data.to_string().as_bytes(),
        &organisation,
    )
    .await;

    let proof = create_proof(
        &context.db.db_conn,
        &verifier_identifier,
        None,
        Some(&proof_schema),
        ProofStateEnum::Pending,
        ProofRole::Verifier,
        "OPENID4VP_DRAFT25",
        Some(&interaction),
        Some(&verifier_key),
        None,
    )
    .await;

    // Send token that only has cat1 but not cat2 (which is required)
    let vp_token_map = json!({
        credential_schema.id.to_string(): [TOKEN2]
    });

    let params = [
        ("vp_token", vp_token_map.to_string()),
        ("state", interaction.id.to_string()),
    ];

    // WHEN
    let url = format!("{base_url}/ssi/openid4vp/draft-25/response");
    let resp = utils::client()
        .post(url)
        .form(&params)
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 400);

    let proof = get_proof(&context.db.db_conn, &proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Error);
    let claims = proof.claims.unwrap();
    assert!(claims.is_empty());
}

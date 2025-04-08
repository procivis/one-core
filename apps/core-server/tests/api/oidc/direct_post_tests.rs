use std::collections::BTreeSet;

use one_core::model::proof::ProofStateEnum;
use serde_json::json;
use uuid::Uuid;

use crate::fixtures::{
    self, create_credential_schema_with_claims, create_proof, create_proof_schema, get_proof,
};
use crate::utils;
use crate::utils::context::TestContext;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};
use crate::utils::server::run_server;

static TOKEN1: &str = "eyJhbGciOiJFRERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MDAxMzgwNTcsImV4cCI6MzMyMzYxMzgwNTcsIm5iZiI6MTcwMDEz\
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
async fn test_direct_post_one_credential_correct() {
    // GIVEN
    let (context, organisation, verifier_did, _) = TestContext::new_with_did(None).await;
    let nonce = "nonce123";

    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (Uuid::new_v4(), "cat1", true, "STRING", false), // Presentation 2 token 1
        (Uuid::new_v4(), "cat2", false, "STRING", false), // Optional - not provided
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

    let interaction_data = json!({
        "nonce": nonce,
        "presentation_definition": {
            "id": "75fcc8e1-a14c-4509-9831-993c5fb37e26",
            "input_descriptors": [{
                "format": {
                    "jwt_vc_json": {
                        "alg": ["EdDSA", "ES256"]
                    }
                },
                "id": "input_0",
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.credentialSchema.id"],
                            "filter": {
                                "type": "string",
                                "const": credential_schema.schema_id
                            }
                        },
                        {
                            "id": new_claim_schemas[0].0,
                            "path": ["$.vc.credentialSubject.cat1"],
                            "optional": false
                        },
                        {
                            "id": new_claim_schemas[1].0,
                            "path": ["$.vc.credentialSubject.cat2"],
                            "optional": true
                        }
                    ]
                }
            }]
        },
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
        &verifier_did,
        None,
        Some(&proof_schema),
        ProofStateEnum::Pending,
        "OPENID4VP_DRAFT20",
        Some(&interaction),
    )
    .await;

    let presentation_submission = json!({
        "definition_id": interaction.id,
        "descriptor_map": [
            {
                "format": "jwt_vp_json",
                "id": "input_0",
                "path": "$",
                "path_nested": {
                        "format": "jwt_vc_json",
                        "path": "$.verifiableCredential[0]"
                    }
            },
        ],
        "id": "318ea550-dbb6-4d6a-9cf2-575bad15c6da"
    });

    let params = [
        (
            "presentation_submission",
            presentation_submission.to_string(),
        ),
        ("vp_token", TOKEN2.to_owned()),
        ("state", interaction.id.to_string()),
    ];

    // WHEN
    let url = format!("{base_url}/ssi/openid4vp/draft-20/response");
    let resp = utils::client()
        .post(url)
        .form(&params)
        .send()
        .await
        .unwrap();

    // THEN
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
        "did:key:z6MkttiJVZB4dwWkF9ALwaELUDq5Jj9j1BhZHNzNcLVNam6n" // hardcoded in TOKEN2
    );

    let claims = proof.claims.unwrap();
    assert!(new_claim_schemas
        .iter()
        .filter(|required_claim| required_claim.2) //required
        .all(|required_claim| claims
            .iter()
            // Values are just keys uppercase
            .any(|db_claim| db_claim.claim.value == required_claim.1.to_ascii_uppercase())));
}

#[tokio::test]
async fn test_direct_post_one_credential_missing_required_claim() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let nonce = "nonce123";

    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (Uuid::new_v4(), "cat1", true, "STRING", false), // Presentation 2 token 1
        (Uuid::new_v4(), "cat2", true, "STRING", false), // required - not provided
    ];

    let credential_schema = create_credential_schema_with_claims(
        &db_conn,
        "NewCredentialSchema",
        &organisation,
        "NONE",
        &new_claim_schemas,
    )
    .await;

    let proof_schema = create_proof_schema(
        &db_conn,
        "Schema1",
        &organisation,
        &[CreateProofInputSchema::from((
            &new_claim_schemas[..],
            &credential_schema,
        ))],
    )
    .await;

    let verifier_did = fixtures::create_did(&db_conn, &organisation, None).await;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let interaction_data = json!({
        "nonce": nonce,
        "presentation_definition": {
            "id": "75fcc8e1-a14c-4509-9831-993c5fb37e26",
            "input_descriptors": [{
                "format": {
                    "jwt_vc_json": {
                        "alg": ["EdDSA", "ES256"]
                    }
                },
                "id": "input_0",
                "constraints": {
                    "fields": [
                        {
                            "id": new_claim_schemas[0].0,
                            "path": ["$.vc.credentialSubject.cat1"],
                            "optional": false
                        },
                        {
                            "id": new_claim_schemas[1].0,
                            "path": ["$.vc.credentialSubject.cat2"],
                            "optional": false
                        }
                    ]
                }
            }]
        },
        "client_id": "client_id",
        "client_id_scheme": "redirect_uri",
        "response_uri": "response_uri"
    });

    let interaction = fixtures::create_interaction(
        &db_conn,
        &base_url,
        interaction_data.to_string().as_bytes(),
        &organisation,
    )
    .await;

    let proof = create_proof(
        &db_conn,
        &verifier_did,
        None,
        Some(&proof_schema),
        ProofStateEnum::Pending,
        "OPENID4VP_DRAFT20",
        Some(&interaction),
    )
    .await;

    let presentation_submission = json!({
        "definition_id": interaction.id,
        "descriptor_map": [
            {
                "format": "jwt_vp_json",
                "id": "input_0",
                "path": "$",
                "path_nested": {
                        "format": "jwt_vc_json",
                        "path": "$.verifiableCredential[0]"
                    }
            },
        ],
        "id": "318ea550-dbb6-4d6a-9cf2-575bad15c6da"
    });

    let params = [
        (
            "presentation_submission",
            presentation_submission.to_string(),
        ),
        ("vp_token", TOKEN2.to_owned()),
        ("state", interaction.id.to_string()),
    ];

    // WHEN
    let _handle = run_server(listener, config, &db_conn).await;

    let url = format!("{base_url}/ssi/openid4vp/draft-20/response");

    let resp = utils::client()
        .post(url)
        .form(&params)
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 400);

    let proof = get_proof(&db_conn, &proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Error);
    let claims = proof.claims.unwrap();
    assert!(claims.is_empty());
}

#[tokio::test]
async fn test_direct_post_multiple_presentations() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let nonce = "nonce123";

    let credential1_claims = vec![
        (Uuid::new_v4(), "name1", true, "STRING", false), // Presentation 1 token 1
        (Uuid::new_v4(), "name2", false, "STRING", false), // Provided, not requested
    ];

    let credential2_claims = vec![
        (Uuid::new_v4(), "pet1", true, "STRING", false), // Presentation 1 token 0
        (Uuid::new_v4(), "pet2", false, "STRING", false), // Provided, not requested
    ];

    let credential3_claims = vec![
        (Uuid::new_v4(), "cat1", true, "STRING", false), // Presentation 2 token 0
        (Uuid::new_v4(), "cat2", false, "STRING", false), // Optional - not provided but requested
    ];

    let credential_schema1 = create_credential_schema_with_claims(
        &db_conn,
        "NameSchema",
        &organisation,
        "NONE",
        &credential1_claims,
    )
    .await;

    let credential_schema2 = create_credential_schema_with_claims(
        &db_conn,
        "PetSchema",
        &organisation,
        "NONE",
        &credential2_claims,
    )
    .await;

    let credential_schema3 = create_credential_schema_with_claims(
        &db_conn,
        "CatSchema",
        &organisation,
        "NONE",
        &credential3_claims,
    )
    .await;

    let proof_input_schemas = [
        CreateProofInputSchema {
            claims: vec![
                CreateProofClaim::from(&credential1_claims[0]), // name1
            ],
            credential_schema: &credential_schema1,
            validity_constraint: None,
        },
        CreateProofInputSchema {
            claims: vec![
                CreateProofClaim::from(&credential2_claims[0]), // pet1
            ],
            credential_schema: &credential_schema2,
            validity_constraint: None,
        },
        CreateProofInputSchema {
            claims: vec![
                CreateProofClaim::from(&credential3_claims[0]), // cat1
                CreateProofClaim::from(&credential3_claims[1]), // cat2 (optional)
            ],
            credential_schema: &credential_schema3,
            validity_constraint: None,
        },
    ];

    let proof_schema =
        create_proof_schema(&db_conn, "Schema1", &organisation, &proof_input_schemas).await;

    let verifier_did = fixtures::create_did(&db_conn, &organisation, None).await;

    let interaction_data = json!({
        "nonce": nonce,
        "presentation_definition": {
            "id": "75fcc8e1-a14c-4509-9831-993c5fb37e26",
            "input_descriptors": [
            {
                "format": {
                    "jwt_vc_json": {
                        "alg": ["EdDSA", "ES256"]
                    }
                },
                "id": "input_0",
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.credentialSchema.id"],
                            "filter": {
                                "type": "string",
                                "const": credential_schema1.schema_id
                            }
                        },
                        {
                            "id": credential1_claims[0].0,
                            "path": ["$.vc.credentialSubject.name1"],
                            "optional": false
                        },
                    ]
                }
            },
            {
                "format": {
                    "jwt_vc_json": {
                        "alg": ["EdDSA", "ES256"]
                    }
                },
                "id": "input_1",
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.credentialSchema.id"],
                            "filter": {
                                "type": "string",
                                "const": credential_schema2.schema_id
                            }
                        },
                        {
                            "id": credential2_claims[0].0,
                            "path": ["$.vc.credentialSubject.pet1"],
                            "optional": false
                        },
                    ]
                }
            },
            {
                "format": {
                    "jwt_vc_json": {
                        "alg": ["EdDSA", "ES256"]
                    }
                },
                "id": "input_2",
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.credentialSchema.id"],
                            "filter": {
                                "type": "string",
                                "const": credential_schema3.schema_id
                            }
                        },
                        {
                            "id": credential3_claims[0].0,
                            "path": ["$.vc.credentialSubject.cat1"],
                            "optional": false
                        },
                        {
                            "id": credential3_claims[1].0,
                            "path": ["$.vc.credentialSubject.cat2"],
                            "optional": true
                        },
                    ]
                }
            }]
        },
        "client_id": "client_id",
        "client_id_scheme": "redirect_uri",
        "response_uri": "response_uri"
    });

    let interaction = fixtures::create_interaction(
        &db_conn,
        &base_url,
        interaction_data.to_string().as_bytes(),
        &organisation,
    )
    .await;

    let proof = create_proof(
        &db_conn,
        &verifier_did,
        None,
        Some(&proof_schema),
        ProofStateEnum::Pending,
        "OPENID4VP_DRAFT20",
        Some(&interaction),
    )
    .await;

    let presentation_submission = json!({
        "definition_id": interaction.id,
        "descriptor_map": [
            {
                "format": "jwt_vp_json",
                "id": "input_0",
                "path": "$[0]",
                "path_nested": {
                        "format": "jwt_vc_json",
                        "path": "$[0].verifiableCredential[1]"
                    }
            },
            {
                "format": "jwt_vp_json",
                "id": "input_1",
                "path": "$[0]",
                "path_nested": {
                        "format": "jwt_vc_json",
                        "path": "$[0].verifiableCredential[0]"
                    }
            },
            {
                "format": "jwt_vp_json",
                "id": "input_2",
                "path": "$[1]",
                "path_nested": {
                        "format": "jwt_vc_json",
                        "path": "$[1].verifiableCredential[0]"
                    }
            }
        ],
        "id": "318ea550-dbb6-4d6a-9cf2-575bad15c6da"
    });

    let params = [
        (
            "presentation_submission",
            presentation_submission.to_string(),
        ),
        ("vp_token", json!([TOKEN1, TOKEN2]).to_string()),
        ("state", interaction.id.to_string()),
    ];

    // WHEN
    let _handle = run_server(listener, config, &db_conn).await;

    let url = format!("{base_url}/ssi/openid4vp/draft-20/response");

    let resp = utils::client()
        .post(url)
        .form(&params)
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 200);

    let proof = get_proof(&db_conn, &proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Accepted);

    let expected_claims: BTreeSet<String> = proof_input_schemas
        .into_iter()
        .flat_map(|c| c.claims)
        .filter_map(|c| c.required.then_some(c.key.to_ascii_uppercase()))
        .collect();

    let claims: BTreeSet<String> = proof
        .claims
        .unwrap()
        .into_iter()
        .map(|c| c.claim.value)
        .collect();

    assert_eq!(expected_claims, claims);

    // TODO: Add additional checks when https://procivis.atlassian.net/browse/ONE-1133 is implemented
}

#[tokio::test]
async fn test_direct_post_wrong_claim_format() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let nonce = "nonce123";

    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (Uuid::new_v4(), "cat1", true, "STRING", false), // Presentation 2 token 1
        (Uuid::new_v4(), "cat2", false, "STRING", false), // Optional - not provided
    ];

    let credential_schema = create_credential_schema_with_claims(
        &db_conn,
        "NewCredentialSchema",
        &organisation,
        "NONE",
        &new_claim_schemas,
    )
    .await;

    let proof_schema = create_proof_schema(
        &db_conn,
        "Schema1",
        &organisation,
        &[CreateProofInputSchema::from((
            &new_claim_schemas[..],
            &credential_schema,
        ))],
    )
    .await;

    let verifier_did = fixtures::create_did(&db_conn, &organisation, None).await;

    let interaction_data = json!({
        "nonce": nonce,
        "presentation_definition": {
            "id": "75fcc8e1-a14c-4509-9831-993c5fb37e26",
            "input_descriptors": [{
                "format": {
                    "vc+sd-jwt": {
                        "kb-jwt_alg_values": ["EdDSA", "ES256"],
                        "sd-jwt_alg_values": ["EdDSA", "ES256"]
                    }
                },
                "id": "input_0",
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.credentialSchema.id"],
                            "filter": {
                                "type": "string",
                                "const": credential_schema.schema_id
                            }
                        },
                        {
                            "id": new_claim_schemas[0].0,
                            "path": ["$.vc.credentialSubject.cat1"],
                            "optional": false
                        },
                        {
                            "id": new_claim_schemas[1].0,
                            "path": ["$.vc.credentialSubject.cat2"],
                            "optional": true
                        }
                    ]
                }
            }]
        },
        "client_id": "client_id",
        "client_id_scheme": "redirect_uri",
        "response_uri": "response_uri"
    });

    let interaction = fixtures::create_interaction(
        &db_conn,
        &base_url,
        interaction_data.to_string().as_bytes(),
        &organisation,
    )
    .await;

    let proof = create_proof(
        &db_conn,
        &verifier_did,
        None,
        Some(&proof_schema),
        ProofStateEnum::Pending,
        "OPENID4VP_DRAFT20",
        Some(&interaction),
    )
    .await;

    let presentation_submission = json!({
        "definition_id": interaction.id,
        "descriptor_map": [
            {
                "format": "jwt_vp_json",
                "id": "input_0",
                "path": "$",
                "path_nested": {
                        "format": "jwt_vc_json",
                        "path": "$.verifiableCredential[0]"
                    }
            },
        ],
        "id": "318ea550-dbb6-4d6a-9cf2-575bad15c6da"
    });

    let params = [
        (
            "presentation_submission",
            presentation_submission.to_string(),
        ),
        ("vp_token", TOKEN2.to_owned()),
        ("state", interaction.id.to_string()),
    ];

    // WHEN
    let _handle = run_server(listener, config, &db_conn).await;

    let url = format!("{base_url}/ssi/openid4vp/draft-20/response");

    let resp = utils::client()
        .post(url)
        .form(&params)
        .send()
        .await
        .unwrap();

    // THEN
    let status_code = resp.status();
    assert_eq!(status_code, 400);

    let proof = get_proof(&db_conn, &proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Error);
    let claims = proof.claims.unwrap();
    assert!(claims.is_empty());
}

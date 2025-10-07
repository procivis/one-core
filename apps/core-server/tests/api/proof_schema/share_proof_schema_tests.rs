use similar_asserts::assert_eq;

use crate::utils::context::TestContext;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};

#[tokio::test]
async fn test_share_proof_schema() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .first()
        .unwrap()
        .schema
        .to_owned();

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
            &organisation,
            vec![CreateProofInputSchema {
                claims: vec![CreateProofClaim {
                    id: claim_schema.id,
                    key: &claim_schema.key,
                    required: true,
                    data_type: &claim_schema.data_type,
                    array: false,
                }],
                credential_schema: &credential_schema,
                validity_constraint: Some(10),
            }],
        )
        .await;

    // WHEN
    let resp = context.api.proof_schemas.share(proof_schema.id).await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    assert!(resp["url"].as_str().unwrap().eq("CORE_URL"));
}

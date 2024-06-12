use crate::utils::{
    context::TestContext,
    db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema},
};

#[tokio::test]
async fn test_delete_proof_schema_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let claim_schema = &credential_schema.claim_schemas.as_ref().unwrap()[0].schema;

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
            &organisation,
            CreateProofInputSchema {
                claims: vec![CreateProofClaim {
                    id: claim_schema.id,
                    key: &claim_schema.key,
                    required: true,
                    data_type: &claim_schema.data_type,
                    array: false,
                }],
                credential_schema: &credential_schema,
                validity_constraint: None,
            },
        )
        .await;

    // WHEN
    let resp = context.api.proof_schemas.delete(proof_schema.id).await;

    // THEN
    assert_eq!(resp.status(), 204);

    let proof_schema = context.db.proof_schemas.get(&proof_schema.id).await;
    assert!(proof_schema.deleted_at.is_some());
}

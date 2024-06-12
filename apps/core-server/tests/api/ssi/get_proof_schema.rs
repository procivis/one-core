use crate::utils::context::TestContext;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_proof_schema_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

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
            CreateProofInputSchema {
                claims: vec![CreateProofClaim {
                    id: claim_schema.id,
                    key: &claim_schema.key,
                    required: true,
                    data_type: &claim_schema.data_type,
                    array: true,
                }],
                credential_schema: &credential_schema,
                validity_constraint: Some(10),
            },
        )
        .await;

    // WHEN
    let resp = context.api.ssi.get_proof_schema(proof_schema.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    resp["id"].assert_eq(&proof_schema.id);
    resp["organisationId"].assert_eq(&organisation.id);
    assert_eq!(resp["name"], "test");
    assert_eq!(resp["proofInputSchemas"].as_array().unwrap().len(), 1);

    let claim_schema_item = &resp["proofInputSchemas"][0]["claimSchemas"][0];
    claim_schema_item["id"].assert_eq(&claim_schema.id);
    assert_eq!(claim_schema_item["key"], claim_schema.key);
    assert_eq!(claim_schema_item["dataType"], claim_schema.data_type);
    assert!(claim_schema_item["required"].as_bool().unwrap());
    assert_eq!(resp["proofInputSchemas"][0]["validityConstraint"], 10);
}

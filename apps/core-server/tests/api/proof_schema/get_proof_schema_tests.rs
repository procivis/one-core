use similar_asserts::assert_eq;
use validator::ValidateLength;

use crate::utils::context::TestContext;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_proof_schema_success() {
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
    let resp = context.api.proof_schemas.get(proof_schema.id).await;

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

#[tokio::test]
async fn test_succeed_to_fetch_claims_just_root_object() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_claims("test", &organisation, "NONE", Default::default())
        .await;

    let root_claim = credential_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        // We only put a root component in proof schema
        .first()
        .unwrap();

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "Test",
            &organisation,
            vec![CreateProofInputSchema {
                claims: vec![CreateProofClaim {
                    id: root_claim.schema.id,
                    key: &root_claim.schema.key,
                    required: true,
                    data_type: &root_claim.schema.data_type,
                    array: false,
                }],
                credential_schema: &credential_schema,
                validity_constraint: Some(10),
            }],
        )
        .await;

    // WHEN
    let resp = context.api.proof_schemas.get(proof_schema.id).await;

    // THEN
    let resp = resp.json_value().await;

    // Response contains all
    assert_eq!(
        resp["proofInputSchemas"][0]["claimSchemas"][0]["claims"]
            .as_array()
            .length(),
        Some(2)
    );
    assert_eq!(
        resp["proofInputSchemas"][0]["claimSchemas"][0]["claims"][1]["claims"]
            .as_array()
            .length(),
        Some(2)
    );
}

#[tokio::test]
async fn test_succeed_to_fetch_claims_nested_root_object() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_claims("test", &organisation, "NONE", Default::default())
        .await;

    let root_claim = credential_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        // We only put a nested (coordinates) root component in proof schema
        .get(2)
        .unwrap();

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "Test",
            &organisation,
            vec![CreateProofInputSchema {
                claims: vec![CreateProofClaim {
                    id: root_claim.schema.id,
                    key: &root_claim.schema.key,
                    required: true,
                    data_type: &root_claim.schema.data_type,
                    array: false,
                }],
                credential_schema: &credential_schema,
                validity_constraint: Some(10),
            }],
        )
        .await;

    // WHEN
    let resp = context.api.proof_schemas.get(proof_schema.id).await;

    // THEN
    let resp = resp.json_value().await;

    // Response contains root component with just one claim (coordinates)
    assert_eq!(
        resp["proofInputSchemas"][0]["claimSchemas"][0]["claims"]
            .as_array()
            .length(),
        Some(1)
    );
    // Coordinates contain both claims (x, y)
    assert_eq!(
        resp["proofInputSchemas"][0]["claimSchemas"][0]["claims"][0]["claims"]
            .as_array()
            .length(),
        Some(2)
    );
}

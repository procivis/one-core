use similar_asserts::assert_eq;

use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_create_proof_schema_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let claims = credential_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .iter()
        .map(|v| (v.schema.id, v.required));

    // WHEN
    let resp = context
        .api
        .proof_schemas
        .create(
            "proof-schema-name",
            organisation.id,
            claims,
            credential_schema.id,
            Some(10),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let proof_schema = context.db.proof_schemas.get(&resp["id"].parse()).await;
    assert_eq!(proof_schema.name, "proof-schema-name");
    assert_eq!(proof_schema.expire_duration, 0);

    let input_schemas = proof_schema.input_schemas.unwrap();
    assert_eq!(input_schemas.len(), 1);
    assert_eq!(input_schemas[0].validity_constraint, Some(10));
    assert_eq!(input_schemas[0].claim_schemas.as_ref().unwrap().len(), 2);
}

#[tokio::test]
async fn test_create_proof_schema_fails_deactivated_organisation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    context.db.organisations.deactivate(&organisation.id).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let claims = credential_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .iter()
        .map(|v| (v.schema.id, v.required));

    // WHEN
    let resp = context
        .api
        .proof_schemas
        .create(
            "proof-schema-name",
            organisation.id,
            claims,
            credential_schema.id,
            Some(10),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0241", resp.error_code().await);
}

#[tokio::test]
async fn test_create_nested_proof_schema_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_claims("test", &organisation, "NONE", Default::default())
        .await;

    //Get only root element
    let claims = credential_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .iter()
        .take(1)
        .map(|v| (v.schema.id, v.required));

    // WHEN
    let resp = context
        .api
        .proof_schemas
        .create(
            "proof-schema-name",
            organisation.id,
            claims,
            credential_schema.id,
            Some(10),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let proof_schema = context.db.proof_schemas.get(&resp["id"].parse()).await;
    assert_eq!(proof_schema.name, "proof-schema-name");
    assert_eq!(proof_schema.expire_duration, 0);

    let input_schemas = proof_schema.input_schemas.unwrap();
    assert_eq!(input_schemas.len(), 1);
    assert_eq!(input_schemas[0].validity_constraint, Some(10));
    assert_eq!(input_schemas[0].claim_schemas.as_ref().unwrap().len(), 1);
}

#[tokio::test]
async fn test_succeed_to_create_nested_proof_schema_without_object_claim() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_claims(
            "test",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                format: Some("SD_JWT".into()),
                ..Default::default()
            },
        )
        .await;

    let claims = credential_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .iter()
        .filter(|v| v.schema.data_type != "OBJECT")
        .map(|v| (v.schema.id, v.required));

    // WHEN
    let resp = context
        .api
        .proof_schemas
        .create(
            "proof-schema-name",
            organisation.id,
            claims,
            credential_schema.id,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn test_create_proof_schema_with_the_same_name_in_different_organisations() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let organisation1 = context.db.organisations.create().await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let claims = credential_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .iter()
        .map(|v| (v.schema.id, v.required));

    let resp = context
        .api
        .proof_schemas
        .create(
            "proof-schema-name",
            organisation.id,
            claims,
            credential_schema.id,
            None,
        )
        .await;

    assert_eq!(resp.status(), 201);

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation1, "NONE", Default::default())
        .await;

    let claims = credential_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .iter()
        .map(|v| (v.schema.id, v.required));

    let resp1 = context
        .api
        .proof_schemas
        .create(
            "proof-schema-name",
            organisation1.id,
            claims,
            credential_schema.id,
            None,
        )
        .await;

    assert_eq!(resp1.status(), 201);
}

#[tokio::test]
async fn test_fail_to_create_proof_schema_with_the_same_name_in_organisation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let claims = credential_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .iter()
        .map(|v| (v.schema.id, v.required));

    // WHEN
    let resp = context
        .api
        .proof_schemas
        .create(
            "proof-schema-name",
            organisation.id,
            claims,
            credential_schema.id,
            None,
        )
        .await;
    assert_eq!(resp.status(), 201);

    let claims = credential_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .iter()
        .map(|v| (v.schema.id, v.required));

    let resp = context
        .api
        .proof_schemas
        .create(
            "proof-schema-name",
            organisation.id,
            claims,
            credential_schema.id,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_create_proof_schema_with_the_same_name_and_organisation_as_deleted_proof_schema() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let claims = credential_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .iter()
        .map(|v| (v.schema.id, v.required));

    let claim_schema = &credential_schema.claim_schemas.as_ref().unwrap()[0].schema;

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "proof-schema-name",
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
                validity_constraint: None,
            }],
        )
        .await;

    context.db.proof_schemas.delete(&proof_schema.id).await;

    // WHEN
    let resp = context
        .api
        .proof_schemas
        .create(
            "proof-schema-name",
            organisation.id,
            claims,
            credential_schema.id,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn test_fail_to_create_proof_schema_from_deleted_credential_schema() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    context
        .db
        .credential_schemas
        .delete(&credential_schema)
        .await;

    let claims = credential_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .iter()
        .map(|v| (v.schema.id, v.required));

    // WHEN
    let resp = context
        .api
        .proof_schemas
        .create(
            "proof-schema-name",
            organisation.id,
            claims,
            credential_schema.id,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_fail_to_create_proof_schema_with_claims_not_related_to_credential_schema() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema1 = context
        .db
        .credential_schemas
        .create("test1", &organisation, "NONE", Default::default())
        .await;

    let credential_schema2 = context
        .db
        .credential_schemas
        .create("test2", &organisation, "NONE", Default::default())
        .await;

    let claims2 = credential_schema2
        .claim_schemas
        .as_ref()
        .unwrap()
        .iter()
        .map(|v| (v.schema.id, v.required));

    // WHEN
    let resp = context
        .api
        .proof_schemas
        .create(
            "proof-schema-name",
            organisation.id,
            claims2,
            credential_schema1.id,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0010");
}

#[tokio::test]
async fn test_fail_missing_validity_constraint_for_lvvc() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema2 = context
        .db
        .credential_schemas
        .create("test2", &organisation, "LVVC", Default::default())
        .await;

    let claims2 = credential_schema2
        .claim_schemas
        .as_ref()
        .unwrap()
        .iter()
        .map(|v| (v.schema.id, v.required));

    // WHEN
    let resp = context
        .api
        .proof_schemas
        .create(
            "proof-schema-name",
            organisation.id,
            claims2,
            credential_schema2.id,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0140");
}

#[tokio::test]
async fn test_fail_to_create_proof_schema_with_mixed_combined_presentation_support() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // Create SWIYU credential schema (doesn't support combined presentations)
    let swiyu_schema = context
        .db
        .credential_schemas
        .create(
            "swiyu-schema",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                format: Some("SD_JWT_VC_SWIYU".into()),
                ..Default::default()
            },
        )
        .await;

    // Create MDOC credential schema (supports combined presentations)
    let mdoc_schema = context
        .db
        .credential_schemas
        .create(
            "mdoc-schema",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                format: Some("MDOC".into()),
                schema_id: Some("org.iso.18013.5.1.mDL".to_string()),
                ..Default::default()
            },
        )
        .await;

    let swiyu_claims: Vec<_> = swiyu_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .iter()
        .map(|v| {
            serde_json::json!({
                "id": v.schema.id,
                "required": v.required
            })
        })
        .collect();

    let mdoc_claims: Vec<_> = mdoc_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .iter()
        .map(|v| {
            serde_json::json!({
                "id": v.schema.id,
                "required": v.required
            })
        })
        .collect();

    // WHEN
    let proof_input_schemas = serde_json::json!([
        {
            "claimSchemas": swiyu_claims,
            "credentialSchemaId": swiyu_schema.id,
        },
        {
            "claimSchemas": mdoc_claims,
            "credentialSchemaId": mdoc_schema.id,
        }
    ]);

    let resp = context
        .api
        .proof_schemas
        .create_with_multiple_schemas("mixed-proof-schema", organisation.id, proof_input_schemas)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0305");
}

#[tokio::test]
async fn test_create_proof_schema_with_both_schemas_supporting_combined_presentation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let mdoc_schema = context
        .db
        .credential_schemas
        .create(
            "mdoc-schema",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                format: Some("MDOC".into()),
                schema_id: Some("org.iso.18013.5.1.mDL".to_string()),
                ..Default::default()
            },
        )
        .await;

    let jwt_schema = context
        .db
        .credential_schemas
        .create(
            "jwt-schema",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                format: Some("JWT".into()),
                ..Default::default()
            },
        )
        .await;

    let mdoc_claims: Vec<_> = mdoc_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .iter()
        .map(|v| {
            serde_json::json!({
                "id": v.schema.id,
                "required": v.required
            })
        })
        .collect();

    let jwt_claims: Vec<_> = jwt_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .iter()
        .map(|v| {
            serde_json::json!({
                "id": v.schema.id,
                "required": v.required
            })
        })
        .collect();

    // WHEN - both schemas supporting combined presentations
    let proof_input_schemas = serde_json::json!([
        {
            "claimSchemas": mdoc_claims,
            "credentialSchemaId": mdoc_schema.id,
        },
        {
            "claimSchemas": jwt_claims,
            "credentialSchemaId": jwt_schema.id,
        }
    ]);

    let resp = context
        .api
        .proof_schemas
        .create_with_multiple_schemas(
            "combined-proof-schema",
            organisation.id,
            proof_input_schemas,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn test_create_proof_schema_with_single_schema_without_combined_presentation_support() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let swiyu_schema = context
        .db
        .credential_schemas
        .create(
            "swiyu-schema",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                format: Some("SD_JWT_VC_SWIYU".into()),
                ..Default::default()
            },
        )
        .await;

    let claims = swiyu_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .iter()
        .map(|v| (v.schema.id, v.required));

    // WHEN
    let resp = context
        .api
        .proof_schemas
        .create(
            "swiyu-proof-schema",
            organisation.id,
            claims,
            swiyu_schema.id,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}

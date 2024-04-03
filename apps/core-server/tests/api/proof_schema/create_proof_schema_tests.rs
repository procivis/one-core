use crate::utils::{
    context::TestContext,
    db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema},
    field_match::FieldHelpers,
};

#[tokio::test]
async fn test_create_proof_schema_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

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
async fn test_create_nested_proof_schema_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_claims("test", &organisation, "NONE", Default::default())
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
    assert_eq!(input_schemas[0].claim_schemas.as_ref().unwrap().len(), 5);
}

#[tokio::test]
async fn test_fail_to_create_nested_proof_schema_without_object_claim() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_claims("test", &organisation, "NONE", Default::default())
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
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_create_proof_schema_with_the_same_name_in_different_organisations() {
    let (context, organisation) = TestContext::new_with_organisation().await;
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
        )
        .await;

    assert_eq!(resp1.status(), 201);
}

#[tokio::test]
async fn test_fail_to_create_proof_schema_with_the_same_name_in_organisation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

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
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_create_proof_schema_with_the_same_name_and_organisation_as_deleted_proof_schema() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

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
            CreateProofInputSchema {
                claims: vec![CreateProofClaim {
                    id: claim_schema.id,
                    key: &claim_schema.key,
                    required: true,
                    data_type: &claim_schema.data_type,
                }],
                credential_schema: &credential_schema,
                validity_constraint: None,
            },
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
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}

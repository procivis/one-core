use crate::utils::{context::TestContext, field_match::FieldHelpers};

#[tokio::test]
async fn test_create_proof_schema_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE")
        .await;

    let claim_schema = &credential_schema.claim_schemas.unwrap()[0].schema;

    // WHEN
    let resp = context
        .api
        .proof_schemas
        .create("proof-schema-name", claim_schema.id, organisation.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let proof_schema = context.db.proof_schemas.get(&resp["id"].parse()).await;
    assert_eq!(proof_schema.name, "proof-schema-name");
    assert_eq!(proof_schema.expire_duration, 0);
    assert_eq!(proof_schema.claim_schemas.unwrap().len(), 1);
    assert_eq!(proof_schema.validity_constraint, Some(10));
}

#[tokio::test]
async fn test_create_proof_schema_with_the_same_name_in_different_organisations() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let organisation1 = context.db.organisations.create().await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE")
        .await;

    let credential_schema1 = context
        .db
        .credential_schemas
        .create("test", &organisation1, "NONE")
        .await;

    let claim_schema = &credential_schema.claim_schemas.unwrap()[0].schema;
    let claim_schema1 = &credential_schema1.claim_schemas.unwrap()[0].schema;

    // WHEN
    let resp = context
        .api
        .proof_schemas
        .create("proof-schema-name", claim_schema.id, organisation.id)
        .await;

    let resp1 = context
        .api
        .proof_schemas
        .create("proof-schema-name", claim_schema1.id, organisation1.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    assert_eq!(resp1.status(), 201);
}

#[tokio::test]
async fn test_fail_to_create_proof_schema_with_the_same_name_in_organisation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE")
        .await;

    let claim_schema = &credential_schema.claim_schemas.unwrap()[0].schema;

    // WHEN
    let resp = context
        .api
        .proof_schemas
        .create("proof-schema-name", claim_schema.id, organisation.id)
        .await;
    assert_eq!(resp.status(), 201);

    let resp = context
        .api
        .proof_schemas
        .create("proof-schema-name", claim_schema.id, organisation.id)
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
        .create("test", &organisation, "NONE")
        .await;

    let claim_schema = &credential_schema.claim_schemas.unwrap()[0].schema;

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "proof-schema-name",
            &organisation,
            &[(
                claim_schema.id,
                &claim_schema.key,
                true,
                &claim_schema.data_type,
            )],
        )
        .await;

    context.db.proof_schemas.delete(&proof_schema.id).await;

    // WHEN
    let resp = context
        .api
        .proof_schemas
        .create("proof-schema-name", claim_schema.id, organisation.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}

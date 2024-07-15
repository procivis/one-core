use one_core::model::credential_schema::CredentialSchemaType;

use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_create_credential_schema_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create(
            "some credential schema",
            organisation.id,
            "JWT",
            "firstName",
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let id = resp["id"].parse();
    let credential_schema = context.db.credential_schemas.get(&id).await;

    assert_eq!(credential_schema.name, "some credential schema");
    assert_eq!(credential_schema.revocation_method, "NONE");
    assert_eq!(credential_schema.organisation.unwrap().id, organisation.id);
    assert_eq!(credential_schema.format, "JWT");
    assert_eq!(credential_schema.claim_schemas.unwrap().len(), 2);
    assert_eq!(
        credential_schema.schema_id,
        format!("{}/ssi/schema/v1/{id}", context.config.app.core_base_url)
    );
    assert_eq!(
        credential_schema.schema_type,
        CredentialSchemaType::ProcivisOneSchema2024
    );
}

#[tokio::test]
async fn test_create_credential_schema_with_the_same_name_in_different_organisations() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let organisation1 = context.db.organisations.create().await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create(
            "some credential schema",
            organisation.id,
            "JWT",
            "firstName",
            None,
        )
        .await;

    let resp1 = context
        .api
        .credential_schemas
        .create(
            "some credential schema",
            organisation1.id,
            "JWT",
            "firstName",
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    assert_eq!(resp1.status(), 201);
}

#[tokio::test]
async fn test_fail_to_create_credential_schema_with_the_same_name_in_organisation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create(
            "some credential schema",
            organisation.id,
            "JWT",
            "firstName",
            None,
        )
        .await;
    assert_eq!(resp.status(), 201);

    let resp = context
        .api
        .credential_schemas
        .create(
            "some credential schema",
            organisation.id,
            "JWT",
            "firstName",
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_create_credential_schema_with_the_same_name_and_organisation_as_deleted_credential_schema(
) {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    let schema_name = "test schema";
    let credential_schema = context
        .db
        .credential_schemas
        .create(schema_name, &organisation, "NONE", Default::default())
        .await;

    context
        .db
        .credential_schemas
        .delete(&credential_schema.id)
        .await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create(schema_name, organisation.id, "JWT", "firstName", None)
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn test_fail_create_credential_schema_with_same_schema_id() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create(
            "some credential schema1",
            organisation.id,
            "MDOC",
            "firstName",
            Some("foo"),
        )
        .await;

    let resp1 = context
        .api
        .credential_schemas
        .create(
            "some credential schema2",
            organisation.id,
            "MDOC",
            "firstName",
            Some("foo"),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    assert_eq!(resp1.status(), 400);
}

#[tokio::test]
async fn test_fail_create_credential_schema_with_firbidden_claim_name() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create(
            "some credential schema1",
            organisation.id,
            "JSON_LD_CLASSIC",
            "id",
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    let err = resp.error_code().await;
    assert_eq!(err, "BR_0145");
}

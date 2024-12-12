use one_core::model::credential_schema::CredentialSchemaType;
use one_core::repository::error::DataLayerError;

use crate::utils::api_clients::credential_schemas::CreateSchemaParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_create_credential_schema_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create(CreateSchemaParams {
            name: "some credential schema".into(),
            organisation_id: organisation.id.into(),
            format: "JWT".into(),
            claim_name: "firstName".into(),
            ..Default::default()
        })
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
        .create(CreateSchemaParams {
            name: "some credential schema".into(),
            organisation_id: organisation.id.into(),
            format: "JWT".into(),
            claim_name: "firstName".into(),
            ..Default::default()
        })
        .await;

    let resp1 = context
        .api
        .credential_schemas
        .create(CreateSchemaParams {
            name: "some credential schema".into(),
            organisation_id: organisation1.id.into(),
            format: "JWT".into(),
            claim_name: "firstName".into(),
            ..Default::default()
        })
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
        .create(CreateSchemaParams {
            name: "some credential schema".into(),
            organisation_id: organisation.id.into(),
            format: "JWT".into(),
            claim_name: "firstName".into(),
            ..Default::default()
        })
        .await;

    assert_eq!(resp.status(), 201);

    let resp = context
        .api
        .credential_schemas
        .create(CreateSchemaParams {
            name: "some credential schema".into(),
            organisation_id: organisation.id.into(),
            format: "JWT".into(),
            claim_name: "firstName".into(),
            ..Default::default()
        })
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
        .create(CreateSchemaParams {
            name: "some credential schema".into(),
            organisation_id: organisation.id.into(),
            format: "JWT".into(),
            claim_name: "firstName".into(),
            ..Default::default()
        })
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
        .create(CreateSchemaParams {
            name: "some credential schema1".into(),
            organisation_id: organisation.id.into(),
            format: "MDOC".into(),
            claim_name: "foo".into(),
            schema_id: Some("foo".into()),
            ..Default::default()
        })
        .await;

    let resp1 = context
        .api
        .credential_schemas
        .create(CreateSchemaParams {
            name: "some credential schema2".into(),
            organisation_id: organisation.id.into(),
            format: "MDOC".into(),
            claim_name: "foo".into(),
            schema_id: Some("foo".into()),
            ..Default::default()
        })
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
        .create(CreateSchemaParams {
            name: "some credential schema".into(),
            organisation_id: organisation.id.into(),
            format: "JSON_LD_CLASSIC".into(),
            claim_name: "id".into(),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    let err = resp.error_code().await;
    assert_eq!(err, "BR_0145");
}

#[tokio::test]
async fn test_fail_to_create_credential_schema_with_layout_properties_when_its_unsupported() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create(CreateSchemaParams {
            name: "some credential schema".into(),
            organisation_id: organisation.id.into(),
            format: "PHYSICAL_CARD".into(),
            claim_name: "firstName".into(),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0131", resp.error_code().await);
}

#[tokio::test]
async fn test_create_credential_schema_revocation_no_suspension_succeeds() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create(CreateSchemaParams {
            name: "some credential schema".into(),
            organisation_id: organisation.id.into(),
            format: "JWT".into(),
            claim_name: "firstName".into(),
            suspension_allowed: Some(true),
            revocation_method: Some("BITSTRINGSTATUSLIST".into()),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn test_create_credential_schema_revocation_no_suspension_fails() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create(CreateSchemaParams {
            name: "some credential schema".into(),
            organisation_id: organisation.id.into(),
            format: "JWT".into(),
            claim_name: "firstName".into(),
            suspension_allowed: Some(true),
            revocation_method: Some("NONE".into()),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0162", resp.error_code().await);
}

#[tokio::test]
async fn test_duplicate_schema() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    context
        .db
        .credential_schemas
        .create_with_result(
            "some credential schema1",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                schema_id: Some("foo".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let res = context
        .db
        .credential_schemas
        .create_with_result(
            "some credential schema1",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                schema_id: Some("foo".to_string()),
                ..Default::default()
            },
        )
        .await;

    assert!(matches!(res, Err(DataLayerError::AlreadyExists)));

    let schemas = context.db.credential_schemas.list().await;
    assert_eq!(schemas.len(), 1);
}

use one_core::model::credential_schema::KeyStorageSecurity;
use one_core::repository::error::DataLayerError;
use similar_asserts::assert_eq;

use crate::utils::api_clients::credential_schemas::{CreateSchemaParams, TestClaim};
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_create_credential_schema_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create(
            CreateSchemaParams {
                name: "some credential schema".into(),
                organisation_id: organisation.id.into(),
                format: "JWT".into(),
                ..Default::default()
            }
            .with_default_claims("firstName".into()),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let id = resp["id"].parse();
    let credential_schema = context.db.credential_schemas.get(&id).await;

    assert_eq!(credential_schema.name, "some credential schema");
    assert_eq!(credential_schema.revocation_method.as_ref(), "NONE");
    assert_eq!(credential_schema.organisation.unwrap().id, organisation.id);
    assert_eq!(credential_schema.format.as_ref(), "JWT");
    let claim_schemas = credential_schema.claim_schemas.as_ref().unwrap();
    assert_eq!(
        claim_schemas
            .iter()
            .filter(|cs| !cs.schema.metadata)
            .count(),
        2
    );
    assert_eq!(
        claim_schemas.iter().filter(|cs| cs.schema.metadata).count(),
        10
    );
    assert_eq!(
        credential_schema.schema_id,
        format!("{}/ssi/schema/v1/{id}", context.config.app.core_base_url)
    );
}

#[tokio::test]
async fn test_create_credential_schema_remote_secure_element_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create(
            CreateSchemaParams {
                name: "some credential schema".into(),
                organisation_id: organisation.id.into(),
                key_storage_security: Some("HIGH".into()),
                format: "JWT".into(),
                ..Default::default()
            }
            .with_default_claims(Default::default()),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let id = resp["id"].parse();
    let credential_schema = context.db.credential_schemas.get(&id).await;

    assert_eq!(credential_schema.name, "some credential schema");
    assert_eq!(
        credential_schema
            .claim_schemas
            .unwrap()
            .iter()
            .filter(|claim_schema| !claim_schema.schema.metadata)
            .count(),
        2
    );
    assert_eq!(
        credential_schema.key_storage_security,
        Some(KeyStorageSecurity::High)
    );
}

#[tokio::test]
async fn test_create_credential_schema_with_the_same_name_in_different_organisations() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let organisation1 = context.db.organisations.create().await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create(
            CreateSchemaParams {
                name: "some credential schema".into(),
                organisation_id: organisation.id.into(),
                format: "JWT".into(),
                ..Default::default()
            }
            .with_default_claims("firstName".into()),
        )
        .await;

    let resp1 = context
        .api
        .credential_schemas
        .create(
            CreateSchemaParams {
                name: "some credential schema".into(),
                organisation_id: organisation1.id.into(),
                format: "JWT".into(),
                ..Default::default()
            }
            .with_default_claims("firstName".into()),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    assert_eq!(resp1.status(), 201);
}

#[tokio::test]
async fn test_fail_to_create_credential_schema_with_the_same_name_in_organisation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create(
            CreateSchemaParams {
                name: "some credential schema".into(),
                organisation_id: organisation.id.into(),
                format: "JWT".into(),
                ..Default::default()
            }
            .with_default_claims("firstName".into()),
        )
        .await;

    assert_eq!(resp.status(), 201);

    let resp = context
        .api
        .credential_schemas
        .create(
            CreateSchemaParams {
                name: "some credential schema".into(),
                organisation_id: organisation.id.into(),
                format: "JWT".into(),
                ..Default::default()
            }
            .with_default_claims("firstName".into()),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_create_credential_schema_with_the_same_name_and_organisation_as_deleted_credential_schema()
 {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let schema_name = "test schema";
    let credential_schema = context
        .db
        .credential_schemas
        .create(schema_name, &organisation, "NONE", Default::default())
        .await;

    context
        .db
        .credential_schemas
        .delete(&credential_schema)
        .await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create(
            CreateSchemaParams {
                name: "some credential schema".into(),
                organisation_id: organisation.id.into(),
                format: "JWT".into(),
                ..Default::default()
            }
            .with_default_claims("firstName".into()),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn test_fail_create_credential_schema_with_same_schema_id() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create(
            CreateSchemaParams {
                name: "some credential schema1".into(),
                organisation_id: organisation.id.into(),
                format: "MDOC".into(),
                schema_id: Some("foo".into()),
                ..Default::default()
            }
            .with_default_claims("foo".into()),
        )
        .await;

    let resp1 = context
        .api
        .credential_schemas
        .create(
            CreateSchemaParams {
                name: "some credential schema2".into(),
                organisation_id: organisation.id.into(),
                format: "MDOC".into(),
                schema_id: Some("foo".into()),
                ..Default::default()
            }
            .with_default_claims("foo".into()),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    assert_eq!(resp1.status(), 400);
}

#[tokio::test]
async fn test_fail_create_credential_schema_with_firbidden_claim_name() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create(
            CreateSchemaParams {
                name: "some credential schema".into(),
                organisation_id: organisation.id.into(),
                format: "JSON_LD_CLASSIC".into(),
                ..Default::default()
            }
            .with_default_claims("id".into()),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    let err = resp.error_code().await;
    assert_eq!(err, "BR_0145");
}

#[tokio::test]
async fn test_fail_to_create_credential_schema_with_layout_properties_when_its_unsupported() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create(CreateSchemaParams {
            name: "some credential schema".into(),
            organisation_id: organisation.id.into(),
            format: "PHYSICAL_CARD".into(),
            claims: vec![TestClaim {
                datatype: "STRING".into(),
                key: "firstName".into(),
                required: true,
                ..Default::default()
            }],
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
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create(
            CreateSchemaParams {
                name: "some credential schema".into(),
                organisation_id: organisation.id.into(),
                format: "JWT".into(),
                suspension_allowed: Some(true),
                revocation_method: Some("BITSTRINGSTATUSLIST".into()),
                ..Default::default()
            }
            .with_default_claims("firstName".into()),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn test_create_credential_schema_revocation_no_suspension_fails() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create(
            CreateSchemaParams {
                name: "some credential schema".into(),
                organisation_id: organisation.id.into(),
                format: "JWT".into(),
                suspension_allowed: Some(true),
                revocation_method: Some("NONE".into()),
                ..Default::default()
            }
            .with_default_claims("firstName".into()),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0162", resp.error_code().await);
}

#[tokio::test]
async fn test_duplicate_schema() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

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

#[tokio::test]
async fn test_fail_create_credential_schema_with_suspension_disabled_for_suspension_only_revocation_method()
 {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create(
            CreateSchemaParams {
                name: "some credential schema".into(),
                organisation_id: organisation.id.into(),
                format: "MDOC".into(),
                revocation_method: Some("MDOC_MSO_UPDATE_SUSPENSION".into()),
                schema_id: Some("schema id".into()),
                suspension_allowed: Some(false),
                ..Default::default()
            }
            .with_default_claims("firstName".into()),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0191", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_create_credential_schema_with_suspension_none_for_suspension_only_revocation_method()
 {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create(
            CreateSchemaParams {
                name: "some credential schema".into(),
                organisation_id: organisation.id.into(),
                format: "MDOC".into(),
                revocation_method: Some("MDOC_MSO_UPDATE_SUSPENSION".into()),
                schema_id: Some("schema id".into()),
                ..Default::default()
            }
            .with_default_claims("firstName".into()),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0191", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_create_credential_schema_invalid_logo() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create(
            CreateSchemaParams {
                name: "some credential schema".into(),
                organisation_id: organisation.id.into(),
                format: "JWT".into(),
                logo: Some("some invalid logo".into()),
                ..Default::default()
            }
            .with_default_claims("firstName".into()),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0193");
}

#[tokio::test]
async fn test_fail_create_credential_schema_deactivated_organisation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    context.db.organisations.deactivate(&organisation.id).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create(
            CreateSchemaParams {
                name: "some credential schema".into(),
                organisation_id: organisation.id.into(),
                format: "JWT".into(),
                ..Default::default()
            }
            .with_default_claims("firstName".into()),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0241", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_create_credential_schema_with_unsupported_data_type() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let mut create_request = CreateSchemaParams {
        name: "Test".into(),
        organisation_id: organisation.id.into(),
        format: "SD_JWT_VC_SWIYU".into(),
        schema_id: Some("ID".into()),
        ..Default::default()
    };
    create_request.claims = vec![TestClaim {
        datatype: "STRING".to_string(),
        key: "firstName".to_string(),
        required: true,
        claims: vec![],
        array: Some(true),
    }];

    // WHEN
    let resp = context.api.credential_schemas.create(create_request).await;

    // THEN
    assert_eq!(resp.status(), 400);
    let err = resp.error_code().await;
    assert_eq!(err, "BR_0245");
}

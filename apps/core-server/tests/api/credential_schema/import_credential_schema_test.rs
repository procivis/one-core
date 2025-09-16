use serde_json::json;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;

#[tokio::test]
async fn test_import_credential_schema_fails_deactivated_organisation() {
    // GIVEN
    let (context, organisation1) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "some credential schema",
            &organisation1,
            "NONE",
            Default::default(),
        )
        .await;

    let credential_schema = context
        .api
        .credential_schemas
        .get(&credential_schema.id)
        .await
        .json_value()
        .await;

    let organisation2 = context.db.organisations.create().await;
    context.db.organisations.deactivate(&organisation2.id).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .import(organisation2.id, credential_schema)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0241", resp.error_code().await);
}

#[tokio::test]
async fn test_import_credential_schema_success_with_same_name() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "some credential schema",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                allow_suspension: Some(false),
                ..Default::default()
            },
        )
        .await;

    let mut credential_schema_json = context
        .api
        .credential_schemas
        .get(&credential_schema.id)
        .await
        .json_value()
        .await;

    let imported_schema_id = Uuid::new_v4();
    credential_schema_json["id"] = json!(imported_schema_id);
    credential_schema_json["schemaId"] = json!(imported_schema_id);

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .import(organisation.id, credential_schema_json)
        .await;

    // then
    assert_eq!(resp.status(), 201);
    let credential_schemas = context.db.credential_schemas.list().await;

    let credential_schema = credential_schemas
        .iter()
        .find(|cs| cs.id == credential_schema.id)
        .unwrap();
    assert_eq!(credential_schema.name, "some credential schema");

    let imported_credential_schema = credential_schemas
        .iter()
        .find(|cs| cs.schema_id == imported_schema_id.to_string())
        .unwrap();
    assert_ne!(imported_credential_schema.name, "some credential schema");
    assert!(
        imported_credential_schema
            .name
            .contains("some credential schema")
    );
}

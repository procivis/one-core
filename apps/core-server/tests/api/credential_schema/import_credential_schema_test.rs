use one_core::model::credential_schema::{TransactionCode, TransactionCodeType};
use rstest::rstest;
use serde_json::json;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;

#[rstest]
#[case::reject_empty_v1("", false, false, false)]
#[case::reject_non_http_v2("ftp://source.example/schema", false, true, false)]
#[case::rehost_empty_v2("", true, true, true)]
#[tokio::test]
async fn test_import_credential_schema_source_url(
    #[case] source_url: &str,
    #[case] rehost: bool,
    #[case] v2: bool,
    #[case] should_succeed: bool,
) {
    let (context, organisation) = TestContext::new_with_organisation(Some(format!(
        "globalSettings:\n  rehostImportedSchemas: {rehost}"
    )))
    .await;
    let schema_id = Uuid::new_v4();
    let mut schema = json!({
        "id": schema_id,
        "createdDate": "2026-05-18T13:53:49Z",
        "lastModified": "2026-05-18T13:53:49Z",
        "name": "Imported schema",
        "organisationId": organisation.id,
        "importedSourceUrl": source_url,
        "claims": [{
            "id": Uuid::new_v4(),
            "createdDate": "2026-05-18T13:53:49Z",
            "lastModified": "2026-05-18T13:53:49Z",
            "key": "name",
            "datatype": "STRING",
            "required": true,
            "array": false,
            "claims": []
        }]
    });
    let response = if v2 {
        schema["formats"] = json!([{"format": "JWT", "ecosystemSchemaId": schema_id}]);
        context
            .api
            .credential_schemas
            .import_v2(organisation.id, schema)
            .await
    } else {
        schema["format"] = json!("JWT");
        schema["schemaId"] = json!(schema_id);
        context
            .api
            .credential_schemas
            .import(organisation.id, schema)
            .await
    };

    if should_succeed {
        assert_eq!(response.status(), 201);
        let id = serde_json::from_value(response.json_value().await["id"].clone()).unwrap();
        let schema = context.db.credential_schemas.get(&id).await;
        let expected_url = if rehost {
            format!("{}/ssi/schema/v2/{id}", context.config.app.core_base_url)
        } else {
            source_url.to_owned()
        };
        assert_eq!(schema.imported_source_url, expected_url);
    } else {
        assert_eq!(response.status(), 400);
        assert_eq!(response.error_code().await, "BR_0512");
        assert!(context.db.credential_schemas.list().await.is_empty());
    }
}

#[tokio::test]
async fn test_import_credential_schema_fails_deactivated_organisation() {
    // GIVEN
    let (context, organisation1) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("some credential schema", &organisation1, Default::default())
        .await;

    let credential_schema = {
        let mut value = context
            .api
            .credential_schemas
            .get(&credential_schema.id)
            .await
            .json_value()
            .await;

        let object = value.as_object_mut().unwrap();
        object.remove("externalSchema");

        value
    };

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
            TestingCreateSchemaParams {
                imported_source_url: Some("https://source.example/schema".to_owned()),
                allow_suspension: Some(false),
                ..Default::default()
            },
        )
        .await;

    let imported_schema_id = Uuid::new_v4();
    let credential_schema_json = {
        let mut value = context
            .api
            .credential_schemas
            .get(&credential_schema.id)
            .await
            .json_value()
            .await;

        let object = value.as_object_mut().unwrap();
        object.remove("externalSchema");
        object.insert("id".to_owned(), json!(imported_schema_id));
        object.insert("schemaId".to_owned(), json!(imported_schema_id));

        value
    };

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

    let mut imported_credential_schema = None;
    for credential_schema in credential_schemas {
        if credential_schema.schema_id().await.unwrap() == imported_schema_id.to_string() {
            imported_credential_schema = Some(credential_schema);
            break;
        }
    }
    let imported_credential_schema = imported_credential_schema.unwrap();
    assert_ne!(&imported_credential_schema.name, "some credential schema");
    assert!(
        imported_credential_schema
            .name
            .contains("some credential schema")
    );
}

#[tokio::test]
async fn test_import_credential_schema_fail_tx_code_length_too_short() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "schema",
            &organisation,
            TestingCreateSchemaParams {
                allow_suspension: Some(false),
                transaction_code: Some(TransactionCode {
                    r#type: TransactionCodeType::Numeric,
                    length: 2,
                    description: None,
                }),
                ..Default::default()
            },
        )
        .await;

    let imported_schema_id = Uuid::new_v4();
    let credential_schema_json = {
        let mut value = context
            .api
            .credential_schemas
            .get(&credential_schema.id)
            .await
            .json_value()
            .await;

        let object = value.as_object_mut().unwrap();
        object.insert("id".to_owned(), json!(imported_schema_id));
        object.insert("schemaId".to_owned(), json!(imported_schema_id));

        value
    };

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .import(organisation.id, credential_schema_json)
        .await;

    // then
    assert_eq!(resp.status(), 400);
    let err = resp.error_code().await;
    assert_eq!(err, "BR_0338");
}

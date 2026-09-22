use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::utils::api_clients::credential_schemas::{CreateSchemaV2Params, TestClaim};
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

fn default_claims() -> Vec<TestClaim> {
    vec![TestClaim {
        datatype: "OBJECT".to_string(),
        key: "root".to_string(),
        required: true,
        claims: vec![TestClaim {
            datatype: "STRING".to_string(),
            key: "firstName".to_string(),
            required: true,
            claims: vec![],
            array: None,
            translations: None,
            mappings: None,
        }],
        array: None,
        translations: None,
        mappings: None,
    }]
}

#[tokio::test]
async fn test_get_credential_schema_v2_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test schema", &organisation, Default::default())
        .await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .get_v2(&credential_schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&credential_schema.id);
    assert!(
        resp["format"].is_null(),
        "format field should not be present in v2"
    );
    assert!(
        resp["schemaId"].is_null(),
        "schemaId field should not be present in v2"
    );
    assert!(
        resp["revocationMethod"].is_null(),
        "revocationMethod field should not be present in v2"
    );

    let formats = resp["formats"]
        .as_array()
        .expect("formats should be an array");
    assert!(!formats.is_empty(), "formats should not be empty");
    assert!(formats[0]["format"].is_string());
    assert!(formats[0]["ecosystemSchemaId"].is_string());

    assert_eq!(resp["claims"].as_array().unwrap().len(), 2);
    assert_eq!(resp["claims"][0]["translations"]["name"]["en"], "firstName");
    assert_eq!(resp["translations"]["name"]["en"], "test schema");
}

#[tokio::test]
async fn test_get_credential_schema_v2_not_found() {
    // GIVEN
    let (context, _organisation) = TestContext::new_with_organisation(None).await;
    let non_existent_id = Uuid::new_v4();

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .get_v2(&non_existent_id)
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_get_credential_schema_v2_created_via_v2_endpoint() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let create_resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![serde_json::json!({ "format": "JWT" })],
            claims: default_claims(),
            batch_size: Some(5),
            ..Default::default()
        })
        .await;
    assert_eq!(create_resp.status(), 201);
    let create_resp = create_resp.json_value().await;
    let id = create_resp["id"].parse::<Uuid>();

    // WHEN
    let resp = context.api.credential_schemas.get_v2(&id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&id);
    assert_eq!(resp["name"], "v2 schema");
    assert_eq!(resp["batchSize"], 5);

    let formats = resp["formats"]
        .as_array()
        .expect("formats should be an array");
    assert_eq!(formats.len(), 1);
    assert_eq!(formats[0]["format"], "JWT");

    assert!(
        resp["format"].is_null(),
        "format field should not be present in v2"
    );
    assert!(
        resp["schemaId"].is_null(),
        "schemaId field should not be present in v2"
    );
    assert!(
        resp["revocationMethod"].is_null(),
        "revocationMethod field should not be present in v2"
    );
}

#[tokio::test]
async fn test_get_credential_schema_v2_with_expiration() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let create_resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "schema with expiration".into(),
            organisation_id: organisation.id.into(),
            formats: vec![serde_json::json!({ "format": "JWT" })],
            claims: default_claims(),
            expiration: Some(63072000),
            ..Default::default()
        })
        .await;
    assert_eq!(create_resp.status(), 201);
    let create_resp = create_resp.json_value().await;
    let id = create_resp["id"].parse::<Uuid>();

    // WHEN
    let resp = context.api.credential_schemas.get_v2(&id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp["expiration"], 63072000);
}

#[tokio::test]
async fn test_get_credential_schema_v2_without_expiration() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test schema", &organisation, Default::default())
        .await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .get_v2(&credential_schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert!(resp["expiration"].is_null());
}

#[tokio::test]
async fn test_get_credential_schema_v2_multiple_formats() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let create_resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "multi-format schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![
                serde_json::json!({ "format": "SD_JWT_VC" }),
                serde_json::json!({ "format": "MDOC", "ecosystemSchemaId": "org.example.test" }),
            ],
            claims: default_claims(),
            ..Default::default()
        })
        .await;
    assert_eq!(create_resp.status(), 201);
    let create_resp = create_resp.json_value().await;
    let id = create_resp["id"].parse::<Uuid>();

    // WHEN
    let resp = context.api.credential_schemas.get_v2(&id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    let formats = resp["formats"]
        .as_array()
        .expect("formats should be an array");
    assert_eq!(formats.len(), 2);

    let format_names: Vec<&str> = formats
        .iter()
        .map(|f| f["format"].as_str().unwrap())
        .collect();
    assert!(format_names.contains(&"SD_JWT_VC"));
    assert!(format_names.contains(&"MDOC"));

    let mdoc_format = formats.iter().find(|f| f["format"] == "MDOC").unwrap();
    assert_eq!(mdoc_format["ecosystemSchemaId"], "org.example.test");
}

#[tokio::test]
async fn test_get_credential_schema_v2_deleted_returns_not_found() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test schema", &organisation, Default::default())
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
        .get_v2(&credential_schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_get_credential_schema_v2_with_allow_revocation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let create_resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "revocable schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![serde_json::json!({ "format": "JWT" })],
            claims: default_claims(),
            allow_revocation: Some(true),
            ..Default::default()
        })
        .await;
    assert_eq!(create_resp.status(), 201);
    let create_resp = create_resp.json_value().await;
    let id = create_resp["id"].parse::<Uuid>();

    // WHEN
    let resp = context.api.credential_schemas.get_v2(&id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp["allowRevocation"], true);
}

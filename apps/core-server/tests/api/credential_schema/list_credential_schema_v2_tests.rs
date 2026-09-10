use serde_json::json;
use similar_asserts::assert_eq;

use crate::utils::api_clients::credential_schemas::{CreateSchemaV2Params, TestClaim};
use crate::utils::context::TestContext;

fn default_claim() -> Vec<TestClaim> {
    vec![TestClaim {
        datatype: "STRING".to_string(),
        key: "test".to_string(),
        required: true,
        ..Default::default()
    }]
}

#[tokio::test]
async fn test_get_list_credential_schema_v2_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let params = CreateSchemaV2Params {
        name: "test-v2".to_string(),
        organisation_id: organisation.id.into(),
        formats: vec![json!({"format": "JWT"})],
        claims: vec![TestClaim {
            datatype: "STRING".to_string(),
            key: "test".to_string(),
            required: true,
            ..Default::default()
        }],
        batch_size: Some(10),
        allow_suspension: Some(true),
        allow_revocation: Some(true),
        expiration: Some(63072000),
        ..Default::default()
    };
    let resp = context.api.credential_schemas.create_v2(params).await;
    assert_eq!(resp.status(), 201);
    let schema_id = resp.json_value().await["id"].as_str().unwrap().to_string();

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .list_v2(0, 10, &organisation.id, None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalItems"], 1);
    let value = &resp["values"][0];
    assert_eq!(value["id"], schema_id);
    assert_eq!(value["name"], "test-v2");
    assert_eq!(value["formats"][0]["format"], "JWT");
    assert_eq!(value["batchSize"], 10);
    assert_eq!(value["allowRevocation"], true);
    assert_eq!(value["expiration"], 63072000);
    assert!(value["format"].is_null());
    assert!(value["schemaId"].is_null());
}

#[tokio::test]
async fn test_get_list_credential_schema_v2_filter_expiration_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "schema-short-expiration".to_string(),
            organisation_id: organisation.id.into(),
            formats: vec![json!({"format": "JWT"})],
            claims: default_claim(),
            expiration: Some(3600),
            ..Default::default()
        })
        .await;

    context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "schema-long-expiration".to_string(),
            organisation_id: organisation.id.into(),
            formats: vec![json!({"format": "JWT"})],
            claims: default_claim(),
            expiration: Some(63072000),
            ..Default::default()
        })
        .await;

    context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "schema-no-expiration".to_string(),
            organisation_id: organisation.id.into(),
            formats: vec![json!({"format": "JWT"})],
            claims: default_claim(),
            ..Default::default()
        })
        .await;

    // WHEN - filter for expiration greater than 1 hour
    let resp = context
        .api
        .credential_schemas
        .list_v2(
            0,
            10,
            &organisation.id,
            None,
            Some("expirationGreaterThan=3600"),
        )
        .await;

    // THEN - only the schema with the 2-year expiration matches
    assert_eq!(resp.status(), 200);
    let resp_json = resp.json_value().await;
    assert_eq!(resp_json["totalItems"], 1);
    assert_eq!(resp_json["values"][0]["name"], "schema-long-expiration");

    // WHEN - filter for expiration less than 1 day
    let resp = context
        .api
        .credential_schemas
        .list_v2(
            0,
            10,
            &organisation.id,
            None,
            Some("expirationLessThan=86400"),
        )
        .await;

    // THEN - only the schema with the 1-hour expiration matches
    assert_eq!(resp.status(), 200);
    let resp_json = resp.json_value().await;
    assert_eq!(resp_json["totalItems"], 1);
    assert_eq!(resp_json["values"][0]["name"], "schema-short-expiration");
}

#[tokio::test]
async fn test_get_list_credential_schema_v2_filter_batch_issuance_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let params1 = CreateSchemaV2Params {
        name: "test-v2-batch".to_string(),
        organisation_id: organisation.id.into(),
        formats: vec![json!({"format": "JWT"})],
        claims: vec![TestClaim {
            datatype: "STRING".to_string(),
            key: "test".to_string(),
            required: true,
            ..Default::default()
        }],
        batch_size: Some(10),
        ..Default::default()
    };
    context.api.credential_schemas.create_v2(params1).await;

    let params2 = CreateSchemaV2Params {
        name: "test-v2-no-batch".to_string(),
        organisation_id: organisation.id.into(),
        formats: vec![json!({"format": "JWT"})],
        claims: vec![TestClaim {
            datatype: "STRING".to_string(),
            key: "test".to_string(),
            required: true,
            ..Default::default()
        }],
        batch_size: None,
        ..Default::default()
    };
    context.api.credential_schemas.create_v2(params2).await;

    // WHEN - filter for batch issuance
    let resp = context
        .api
        .credential_schemas
        .list_v2(
            0,
            10,
            &organisation.id,
            None,
            Some("usesBatchIssuance=true"),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp_json = resp.json_value().await;
    assert_eq!(resp_json["totalItems"], 1);
    assert_eq!(resp_json["values"][0]["name"], "test-v2-batch");

    // WHEN - filter for NO batch issuance
    let resp = context
        .api
        .credential_schemas
        .list_v2(
            0,
            10,
            &organisation.id,
            None,
            Some("usesBatchIssuance=false"),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp_json = resp.json_value().await;
    assert_eq!(resp_json["totalItems"], 1);
    assert_eq!(resp_json["values"][0]["name"], "test-v2-no-batch");

    // WHEN - filter for multi-format
    let params3 = CreateSchemaV2Params {
        name: "test-v2-multi".to_string(),
        organisation_id: organisation.id.into(),
        formats: vec![
            json!({"format": "JWT"}),
            json!({"format": "SD_JWT_VC_SWIYU", "ecosystemSchemaId": "multi-swiyu"}),
        ],
        claims: vec![TestClaim {
            datatype: "STRING".to_string(),
            key: "test".to_string(),
            required: true,
            ..Default::default()
        }],
        ..Default::default()
    };
    let resp = context.api.credential_schemas.create_v2(params3).await;
    assert_eq!(resp.status(), 201);

    let resp = context
        .api
        .credential_schemas
        .list_v2(
            0,
            10,
            &organisation.id,
            None,
            Some("isMultiformatSchema=true"),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp_json = resp.json_value().await;
    assert_eq!(resp_json["totalItems"], 1);
    assert_eq!(resp_json["values"][0]["name"], "test-v2-multi");
}

#[tokio::test]
async fn test_get_list_credential_schema_v2_filter_ids_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let resp_a = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "schema-a".to_string(),
            organisation_id: organisation.id.into(),
            formats: vec![json!({"format": "JWT"})],
            claims: default_claim(),
            ..Default::default()
        })
        .await;
    let id_a = resp_a.json_value().await["id"]
        .as_str()
        .unwrap()
        .to_string();

    let resp_b = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "schema-b".to_string(),
            organisation_id: organisation.id.into(),
            formats: vec![json!({"format": "JWT"})],
            claims: default_claim(),
            ..Default::default()
        })
        .await;
    let id_b = resp_b.json_value().await["id"]
        .as_str()
        .unwrap()
        .to_string();

    context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "schema-c".to_string(),
            organisation_id: organisation.id.into(),
            formats: vec![json!({"format": "JWT"})],
            claims: default_claim(),
            ..Default::default()
        })
        .await;

    // WHEN - filter by two database UUIDs
    let resp = context
        .api
        .credential_schemas
        .list_v2(
            0,
            10,
            &organisation.id,
            None,
            Some(&format!("ids[]={id_a}&ids[]={id_b}")),
        )
        .await;

    // THEN - only the two requested schemas are returned
    assert_eq!(resp.status(), 200);
    let resp_json = resp.json_value().await;
    assert_eq!(resp_json["totalItems"], 2);
    let names: Vec<&str> = resp_json["values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"schema-a"));
    assert!(names.contains(&"schema-b"));
    assert!(!names.contains(&"schema-c"));
}

#[tokio::test]
async fn test_get_list_credential_schema_v2_filter_ecosystem_schema_ids_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "schema-a".to_string(),
            organisation_id: organisation.id.into(),
            formats: vec![json!({"format": "SD_JWT_VC_SWIYU", "ecosystemSchemaId": "schema-id-a"})],
            claims: default_claim(),
            ..Default::default()
        })
        .await;

    context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "schema-b".to_string(),
            organisation_id: organisation.id.into(),
            formats: vec![json!({"format": "SD_JWT_VC_SWIYU", "ecosystemSchemaId": "schema-id-b"})],
            claims: default_claim(),
            ..Default::default()
        })
        .await;

    context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "schema-c".to_string(),
            organisation_id: organisation.id.into(),
            formats: vec![json!({"format": "SD_JWT_VC_SWIYU", "ecosystemSchemaId": "schema-id-c"})],
            claims: default_claim(),
            ..Default::default()
        })
        .await;

    // WHEN - filter by two schema IDs
    let resp = context
        .api
        .credential_schemas
        .list_v2(
            0,
            10,
            &organisation.id,
            None,
            Some("ecosystemSchemaIds[]=schema-id-a&ecosystemSchemaIds[]=schema-id-b"),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp_json = resp.json_value().await;
    assert_eq!(resp_json["totalItems"], 2);
    let names: Vec<&str> = resp_json["values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"schema-a"));
    assert!(names.contains(&"schema-b"));
    assert!(!names.contains(&"schema-c"));
}

#[tokio::test]
async fn test_get_list_credential_schema_v2_filter_ecosystem_schema_ids_multiformat_success() {
    // GIVEN - a multi-format schema where ecosystemSchemaId belongs to one of its formats
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "schema-multi".to_string(),
            organisation_id: organisation.id.into(),
            formats: vec![
                json!({"format": "JWT"}),
                json!({"format": "SD_JWT_VC_SWIYU", "ecosystemSchemaId": "schema-multi-swiyu"}),
            ],
            claims: default_claim(),
            ..Default::default()
        })
        .await;

    context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "schema-other".to_string(),
            organisation_id: organisation.id.into(),
            formats: vec![json!({"format": "JWT"})],
            claims: default_claim(),
            ..Default::default()
        })
        .await;

    // WHEN - filter by the SD_JWT_VC_SWIYU schemaId of the multi-format schema
    let resp = context
        .api
        .credential_schemas
        .list_v2(
            0,
            10,
            &organisation.id,
            None,
            Some("ecosystemSchemaIds[]=schema-multi-swiyu"),
        )
        .await;

    // THEN - returns the multi-format schema even though the match is on its second format
    assert_eq!(resp.status(), 200);
    let resp_json = resp.json_value().await;
    assert_eq!(resp_json["totalItems"], 1);
    assert_eq!(resp_json["values"][0]["name"], "schema-multi");
}

#[tokio::test]
async fn test_get_list_credential_schema_v2_filter_formats_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "jwt-schema".to_string(),
            organisation_id: organisation.id.into(),
            formats: vec![json!({"format": "JWT"})],
            claims: default_claim(),
            ..Default::default()
        })
        .await;

    context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "swiyu-schema".to_string(),
            organisation_id: organisation.id.into(),
            formats: vec![
                json!({"format": "SD_JWT_VC_SWIYU", "ecosystemSchemaId": "swiyu-only-id"}),
            ],
            claims: default_claim(),
            ..Default::default()
        })
        .await;

    context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "multi-schema".to_string(),
            organisation_id: organisation.id.into(),
            formats: vec![
                json!({"format": "JWT"}),
                json!({"format": "SD_JWT_VC_SWIYU", "ecosystemSchemaId": "multi-swiyu-id"}),
            ],
            claims: default_claim(),
            ..Default::default()
        })
        .await;

    // WHEN - filter by JWT format
    let resp = context
        .api
        .credential_schemas
        .list_v2(0, 10, &organisation.id, None, Some("formats[]=JWT"))
        .await;

    // THEN - returns both the jwt-only schema and the multi-format schema
    assert_eq!(resp.status(), 200);
    let resp_json = resp.json_value().await;
    assert_eq!(resp_json["totalItems"], 2);
    let names: Vec<&str> = resp_json["values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"jwt-schema"));
    assert!(names.contains(&"multi-schema"));
    assert!(!names.contains(&"swiyu-schema"));
}

#[tokio::test]
async fn test_get_list_credential_schema_v2_sort_case_insensitive() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "first".to_string(),
            organisation_id: organisation.id.into(),
            formats: vec![json!({"format": "JWT"})],
            claims: default_claim(),
            ..Default::default()
        })
        .await;
    context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "Second".to_string(),
            organisation_id: organisation.id.into(),
            formats: vec![json!({"format": "JWT"})],
            claims: default_claim(),
            ..Default::default()
        })
        .await;
    context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "THIRD".to_string(),
            organisation_id: organisation.id.into(),
            formats: vec![json!({"format": "JWT"})],
            claims: default_claim(),
            ..Default::default()
        })
        .await;

    // WHEN - sort by name
    let resp = context
        .api
        .credential_schemas
        .list_v2(0, 10, &organisation.id, None, Some("sort=name"))
        .await;

    // THEN - the schemas are sorted case-insesitive
    assert_eq!(resp.status(), 200);
    let resp_json = resp.json_value().await;
    assert_eq!(resp_json["totalItems"], 3);
    let names: Vec<&str> = resp_json["values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["name"].as_str().unwrap())
        .collect();
    assert_eq!(names[0], "first");
    assert_eq!(names[1], "Second");
    assert_eq!(names[2], "THIRD");
}

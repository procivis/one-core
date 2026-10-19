use serde_json::{Value, json};
use similar_asserts::assert_eq;

use crate::utils::api_clients::credential_schemas::{CreateSchemaV2Params, TestClaim};
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;

#[tokio::test]
async fn test_vct_metadata_not_found() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_sd_jwt_vc_type_metadata(organisation.id, "not_found")
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_vct_metadata_simple() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let vct_type = "test_id";
    let schema_name = "test_name";
    let vct = format!(
        "{}/ssi/vct/v1/{}/{vct_type}",
        context.config.app.core_base_url, organisation.id
    );
    context
        .db
        .credential_schemas
        .create(
            schema_name,
            &organisation,
            TestingCreateSchemaParams {
                schema_id: Some(vct.clone()),
                format: Some("SD_JWT_VC".into()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_sd_jwt_vc_type_metadata(organisation.id, vct_type)
        .await;

    // THEN
    let default_language = &context.config.core.global_settings.default_language;
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json_value().await;
    assert_eq!(resp["vct"], json!(vct));
    assert_eq!(resp["name"], json!(vct_type));
    assert_eq!(resp["display"].as_array().unwrap().len(), 1);
    assert_eq!(resp["display"][0]["name"], json!(schema_name));
    assert_eq!(
        resp["display"][0]["rendering"],
        json!({
          "simple": {
            "background_color": "#DA2727"
          }
        })
    );
    assert!(resp["layout_properties"].is_object()); // layout_properties is present
    assert_eq!(resp["claims"].as_array().unwrap().len(), 2);
    // claims array is not ordered
    assert!(resp["claims"].as_array().unwrap().contains(&json!({
      "path": [
        "firstName"
      ],
      "display": [
        {
          "locale": default_language,
          "label": "firstName"
        }
      ],
      "sd": "allowed"
    })));
    assert!(resp["claims"].as_array().unwrap().contains(&json!({
      "path": [
        "isOver18"
      ],
      "display": [
        {
          "locale": default_language,
          "label": "isOver18"
        }
      ],
      "sd": "allowed"
    })));
}

#[tokio::test]
async fn test_vct_metadata_nested_claims() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let vct_type = "test_id";
    let schema_name = "test_name";
    let vct = format!(
        "{}/ssi/vct/v1/{}/{vct_type}",
        context.config.app.core_base_url, organisation.id
    );
    context
        .db
        .credential_schemas
        .create_with_array_claims(
            schema_name,
            &organisation,
            TestingCreateSchemaParams {
                schema_id: Some(vct.clone()),
                format: Some("SD_JWT_VC".into()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_sd_jwt_vc_type_metadata(organisation.id, vct_type)
        .await;

    // THEN
    let default_language = &context.config.core.global_settings.default_language;
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json_value().await;
    // VCT metadata _must_ be deterministic because otherwise vct subresource integrity is broken
    let expected = json!({
      "claims": [
        {
          "display": [
            {
              "label": "namespace",
              "locale": default_language
            }
          ],
          "path": [
            "namespace"
          ],
          "sd": "allowed"
        },
        {
          "display": [
            {
              "label": "root_array",
              "locale": default_language
            }
          ],
          "path": [
            "namespace",
            "root_array"
          ],
          "sd": "allowed"
        },
        {
          "display": [
            {
              "label": "nested",
              "locale": default_language
            }
          ],
          "path": [
            "namespace",
            "root_array",
            null,
            "nested"
          ],
          "sd": "allowed"
        },
        {
          "display": [
            {
              "label": "field",
              "locale": default_language
            }
          ],
          "path": [
            "namespace",
            "root_array",
            null,
            "nested",
            null,
            "field"
          ],
          "sd": "allowed"
        },
        {
          "display": [
            {
              "label": "root_field",
              "locale": default_language
            }
          ],
          "path": [
            "namespace",
            "root_field"
          ],
          "sd": "allowed"
        }
      ],
      "display": [
        {
          "locale": default_language,
          "name": "test_name",
        }
      ],
      "name": "test_id",
      "vct": vct
    });
    assert_eq!(resp, expected);
}

#[tokio::test]
async fn test_vct_metadata_v2_not_found() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_sd_jwt_vc_type_metadata_v2(organisation.id, "not_found", "SD_JWT_VC")
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_vct_metadata_v2_simple() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema_id = "test_id";
    let schema_name = "test_name";
    let vct = format!(
        "{}/ssi/vct/v2/{}/{credential_schema_id}/SD_JWT_VC",
        context.config.app.core_base_url, organisation.id
    );

    context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: schema_name.to_string(),
            organisation_id: organisation.id.into(),
            formats: vec![json!({ "format": "SD_JWT_VC", "ecosystemSchemaId": vct.clone() })],
            claims: vec![
                TestClaim {
                    datatype: "STRING".to_string(),
                    key: "firstName".to_string(),
                    required: true,
                    claims: vec![],
                    array: None,
                    translations: None,
                    mappings: None,
                },
                TestClaim {
                    datatype: "STRING".to_string(),
                    key: "isOver18".to_string(),
                    required: true,
                    claims: vec![],
                    array: None,
                    translations: None,
                    mappings: None,
                },
            ],
            ..Default::default()
        })
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_sd_jwt_vc_type_metadata_v2(organisation.id, credential_schema_id, "SD_JWT_VC")
        .await;

    // THEN
    let default_language = &context.config.core.global_settings.default_language;
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json_value().await;
    assert_eq!(resp["vct"], json!(vct));
    assert_eq!(resp["name"], json!(credential_schema_id));
    assert_eq!(resp["display"].as_array().unwrap().len(), 1);
    assert_eq!(resp["display"][0]["name"], json!(schema_name));
    assert!(resp["display"][0].get("lang").is_none());
    let claims = resp["claims"].as_array().unwrap();
    assert_eq!(claims.len(), 2);
    assert!(claims.contains(&json!({
        "path": ["firstName"],
        "display": [{"locale": default_language, "label": "firstName"}],
        "sd": "allowed"
    })));
    assert!(claims.contains(&json!({
        "path": ["isOver18"],
        "display": [{"locale": default_language, "label": "isOver18"}],
        "sd": "allowed"
    })));
}

#[tokio::test]
async fn test_vct_metadata_v2_with_format_wrong_format_returns_not_found() {
    // GIVEN - schema exists with SD_JWT_VC format only
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema_id = "test_id";
    let sd_jwt_vc_vct = format!(
        "{}/ssi/vct/v2/{}/{credential_schema_id}/SD_JWT_VC",
        context.config.app.core_base_url, organisation.id
    );

    context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "test_name".to_string(),
            organisation_id: organisation.id.into(),
            formats: vec![json!({ "format": "SD_JWT_VC", "schemaId": sd_jwt_vc_vct })],
            claims: vec![TestClaim {
                datatype: "STRING".to_string(),
                key: "name".to_string(),
                required: true,
                claims: vec![],
                array: None,
                translations: None,
                mappings: None,
            }],
            ..Default::default()
        })
        .await;

    // WHEN — querying with JWT format constructs a different VCT URL, not matching the schema
    let resp = context
        .api
        .ssi
        .get_sd_jwt_vc_type_metadata_v2(organisation.id, credential_schema_id, "JWT")
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_vct_metadata_v2_swiyu_display_contains_lang() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema_id = "test_id";
    let schema_name = "test_name";
    let vct = format!(
        "{}/ssi/vct/v2/{}/{credential_schema_id}/SD_JWT_VC_SWIYU",
        context.config.app.core_base_url, organisation.id
    );

    context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: schema_name.to_string(),
            organisation_id: organisation.id.into(),
            formats: vec![json!({ "format": "SD_JWT_VC_SWIYU", "ecosystemSchemaId": vct.clone() })],
            claims: vec![TestClaim {
                datatype: "STRING".to_string(),
                key: "firstName".to_string(),
                required: true,
                claims: vec![],
                array: None,
                translations: None,
                mappings: None,
            }],
            ..Default::default()
        })
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_sd_jwt_vc_type_metadata_v2(organisation.id, credential_schema_id, "SD_JWT_VC_SWIYU")
        .await;

    // THEN
    let default_language = &context.config.core.global_settings.default_language;
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json_value().await;
    assert_eq!(resp["vct"], json!(vct));
    assert_eq!(resp["display"].as_array().unwrap().len(), 1);
    assert_eq!(resp["display"][0]["name"], json!(schema_name));
    assert_eq!(resp["display"][0]["locale"], json!(default_language));
    assert_eq!(resp["display"][0]["lang"], json!(default_language));
    // claim display entries stay standard
    assert_eq!(
        resp["claims"],
        json!([{
            "path": ["firstName"],
            "display": [{"locale": default_language, "label": "firstName"}],
            "sd": "allowed"
        }])
    );
}

#[tokio::test]
async fn test_vct_metadata_swiyu_display_contains_lang() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let vct_type = "test_id";
    let schema_name = "test_name";
    let vct = format!(
        "{}/ssi/vct/v1/{}/{vct_type}",
        context.config.app.core_base_url, organisation.id
    );
    context
        .db
        .credential_schemas
        .create(
            schema_name,
            &organisation,
            TestingCreateSchemaParams {
                schema_id: Some(vct.clone()),
                format: Some("SD_JWT_VC_SWIYU".into()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_sd_jwt_vc_type_metadata(organisation.id, vct_type)
        .await;

    // THEN
    let default_language = &context.config.core.global_settings.default_language;
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json_value().await;
    assert_eq!(resp["display"].as_array().unwrap().len(), 1);
    assert_eq!(resp["display"][0]["locale"], json!(default_language));
    assert_eq!(resp["display"][0]["lang"], json!(default_language));
}

#[tokio::test]
async fn test_vct_metadata_v2_display_per_translation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema_id = "test_id";
    let vct = format!(
        "{}/ssi/vct/v2/{}/{credential_schema_id}/SD_JWT_VC_SWIYU",
        context.config.app.core_base_url, organisation.id
    );

    context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "test_name".to_string(),
            organisation_id: organisation.id.into(),
            formats: vec![json!({ "format": "SD_JWT_VC_SWIYU", "ecosystemSchemaId": vct.clone() })],
            claims: vec![TestClaim {
                datatype: "STRING".to_string(),
                key: "firstName".to_string(),
                required: true,
                claims: vec![],
                array: None,
                translations: Some(json!({
                    "name": { "en": "First name", "de": "Vorname" }
                })),
                mappings: None,
            }],
            translations: Some(json!({
                "name": { "en": "Name", "de": "Name DE" },
                "description": { "de": "Beschreibung" }
            })),
            ..Default::default()
        })
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_sd_jwt_vc_type_metadata_v2(organisation.id, credential_schema_id, "SD_JWT_VC_SWIYU")
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json_value().await;
    let rendering = &resp["display"][0]["rendering"];
    assert_eq!(
        resp["display"],
        json!([
            {
                "locale": "de",
                "lang": "de",
                "name": "Name DE",
                "description": "Beschreibung",
                "rendering": rendering,
            },
            {
                "locale": "en",
                "lang": "en",
                "name": "Name",
                "rendering": rendering,
            }
        ])
    );
    assert_eq!(
        resp["claims"],
        json!([{
            "path": ["firstName"],
            "display": [
                { "locale": "de", "label": "Vorname" },
                { "locale": "en", "label": "First name" }
            ],
            "sd": "allowed"
        }])
    );
}

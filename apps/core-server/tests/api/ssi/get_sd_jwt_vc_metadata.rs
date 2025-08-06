use serde_json::{Value, json};
use similar_asserts::assert_eq;

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
            "NONE",
            TestingCreateSchemaParams {
                schema_id: Some(vct.clone()),
                format: Some("SD_JWT_VC".to_string()),
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
            "backgroundColor": "#DA2727",
            "textColor": "#FFFFFF"
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
          "lang": "en-US",
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
          "lang": "en-US",
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
            "NONE",
            TestingCreateSchemaParams {
                schema_id: Some(vct.clone()),
                format: Some("SD_JWT_VC".to_string()),
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
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json_value().await;
    // VCT metadata _must_ be deterministic because otherwise vct subresource integrity is broken
    let expected = json!({
      "claims": [
        {
          "display": [
            {
              "label": "namespace",
              "lang": "en-US"
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
              "lang": "en-US"
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
              "lang": "en-US"
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
              "lang": "en-US"
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
              "lang": "en-US"
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
          "lang": "en-US",
          "name": "test_name",
          "rendering": {
            "simple": {
              "textColor": "#FFFFFF"
            }
          }
        }
      ],
      "name": "test_id",
      "vct": vct
    });
    assert_eq!(resp, expected);
}

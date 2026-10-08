use similar_asserts::assert_eq;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_openapi_yaml() {
    let context = TestContext::new(None).await;

    let resp = context.api.other.openapi_yaml().await;
    assert_eq!(200, resp.status());
}

#[tokio::test]
async fn test_openapi_yaml_disabled() {
    let config = indoc::indoc! {"
      app:
        enableOpenApi: false
    "}
    .to_string();
    let context = TestContext::new(Some(config.to_string())).await;

    let resp = context.api.other.openapi_yaml().await;
    assert_eq!(404, resp.status());
}

#[tokio::test]
async fn test_openapi_json() {
    let context = TestContext::new(None).await;

    let resp = context.api.other.openapi_json().await;
    assert_eq!(200, resp.status());
}

#[tokio::test]
async fn test_openapi_schema_regressions() {
    let context = TestContext::new(None).await;
    let openapi: serde_json::Value = context.api.other.openapi_json().await.json().await;
    let schemas = &openapi["components"]["schemas"];

    for (schema, property) in [
        ("CredentialListItemSchemaRestDTO", "revocationMethod"),
        ("CredentialListItemSchemaRestDTO", "format"),
        (
            "CredentialTrustInformationDetailResponseRestDTO",
            "eudiEcosystem",
        ),
        ("CredentialDetailSchemaResponseRestDTO", "revocationMethod"),
        ("CredentialDetailSchemaResponseRestDTO", "format"),
        (
            "ProofTrustInformationDetailResponseRestDTO",
            "eudiEcosystem",
        ),
    ] {
        assert_eq!(
            Some(true),
            find_property(&schemas[schema], property)
                .and_then(|schema| schema["deprecated"].as_bool()),
            "{schema}.{property} should be deprecated in OpenAPI",
        );
    }

    for (path, component) in [
        (
            "/api/credential/v1/{id}/trust-detail",
            "CredentialTrustInformationDetailResponseRestDTO",
        ),
        (
            "/api/proof-request/v1/{id}/trust-detail",
            "ProofTrustInformationDetailResponseRestDTO",
        ),
    ] {
        let schema = &openapi["paths"][path]["get"]["responses"]["200"]["content"]["application/json"]
            ["schema"];
        assert_eq!(
            Some(component),
            schema["$ref"]
                .as_str()
                .and_then(|reference| reference.strip_prefix("#/components/schemas/")),
            "{path} should reference its modified component schema",
        );
    }

    let schema = &openapi["paths"]["/api/credential-schema/v1"]["get"]["responses"]["200"]["content"]
        ["application/json"]["schema"];

    assert_eq!(
        Some("object"),
        schema["type"].as_str(),
        "credential schema list response should resolve to an object schema",
    );
    assert_eq!(
        Some("#/components/schemas/CredentialSchemaListItemResponseRestDTO"),
        schema["properties"]["values"]["items"]["$ref"].as_str(),
        "credential schema list values should reference the list item schema",
    );

    assert_eq!(
        Some("string"),
        schemas["JwkUse"]["type"].as_str(),
        "JwkUse should be a plain string, its unknown variant is untagged",
    );
}

fn find_property<'a>(
    schema: &'a serde_json::Value,
    property: &str,
) -> Option<&'a serde_json::Value> {
    schema["properties"].get(property).or_else(|| {
        schema["allOf"]
            .as_array()?
            .iter()
            .find_map(|schema| find_property(schema, property))
    })
}

#[tokio::test]
async fn test_openapi_json_disabled() {
    let config = indoc::indoc! {"
      app:
        enableOpenApi: false
    "}
    .to_string();
    let context = TestContext::new(Some(config.to_string())).await;

    let resp = context.api.other.openapi_json().await;
    assert_eq!(404, resp.status());
}

use serde_json::Value;
use similar_asserts::assert_eq;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_get_credential_issuer_metadata_jwt() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_hell("test_schema", &organisation, "NONE", Default::default())
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .openid_credential_issuer_final1("OPENID4VCI_FINAL1", credential_schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    let issuer = format!(
        "{}/ssi/openid4vci/final-1.0/OPENID4VCI_FINAL1/{}",
        context.config.app.core_base_url, credential_schema.id
    );

    assert_eq!(issuer, resp["credential_issuer"]);
    assert_eq!(
        format!(
            "{}/ssi/openid4vci/final-1.0/{}/credential",
            context.config.app.core_base_url, credential_schema.id
        ),
        resp["credential_endpoint"]
    );
    assert_eq!(
        format!(
            "{}/ssi/openid4vci/final-1.0/OPENID4VCI_FINAL1/nonce",
            context.config.app.core_base_url
        ),
        resp["nonce_endpoint"]
    );

    let credentials = resp["credential_configurations_supported"]
        .as_object()
        .unwrap();
    assert!(!credentials.is_empty());

    // Check the credential format and metadata structure
    assert_eq!(
        credentials[&credential_schema.schema_id]["format"],
        "jwt_vc_json"
    );

    // Check display properties are present
    let display = &credentials[&credential_schema.schema_id]["credential_metadata"]["display"][0];
    assert_eq!(display["name"], "test_schema");
    assert_eq!(display["locale"], "en");

    // Check claims structure
    let claims = &credentials[&credential_schema.schema_id]["credential_metadata"]["claims"];
    assert_expected_claims(claims);
}

fn assert_expected_claims(claims: &Value) {
    let claims_array = claims.as_array().unwrap();
    assert_eq!(claims_array.len(), 10); // Total number of claims including nested ones

    // Helper function to find a claim by path
    let find_claim = |path: &[&str]| -> &Value {
        claims_array
            .iter()
            .find(|claim| {
                let claim_path = claim["path"].as_array().unwrap();
                claim_path.len() == path.len()
                    && claim_path
                        .iter()
                        .zip(path.iter())
                        .all(|(a, b)| a.as_str().unwrap() == *b)
            })
            .unwrap()
    };

    // Check root level claims
    let name_claim = find_claim(&["name"]);
    assert_eq!(name_claim["mandatory"], true);
    assert_eq!(name_claim["display"][0]["name"], "name");

    let string_array_claim = find_claim(&["string_array"]);
    assert_eq!(string_array_claim["mandatory"], true);
    assert_eq!(string_array_claim["display"][0]["name"], "string_array");

    // Check nested claims
    let address_street_claim = find_claim(&["address", "street"]);
    assert_eq!(address_street_claim["mandatory"], true);
    assert_eq!(address_street_claim["display"][0]["name"], "street");

    let coordinates_x_claim = find_claim(&["address", "coordinates", "x"]);
    assert_eq!(coordinates_x_claim["mandatory"], true);
    assert_eq!(coordinates_x_claim["display"][0]["name"], "x");

    let coordinates_y_claim = find_claim(&["address", "coordinates", "y"]);
    assert_eq!(coordinates_y_claim["mandatory"], true);
    assert_eq!(coordinates_y_claim["display"][0]["name"], "y");

    // Check array claims
    let nested_string_array_claim = find_claim(&["address", "coordinates", "string_array"]);
    assert_eq!(nested_string_array_claim["mandatory"], true);
    assert_eq!(
        nested_string_array_claim["display"][0]["name"],
        "string_array"
    );

    // Check object array claims
    let object_array_field1_claim = find_claim(&["object_array", "field1"]);
    assert_eq!(object_array_field1_claim["mandatory"], true);
    assert_eq!(object_array_field1_claim["display"][0]["name"], "field1");

    let object_array_field2_claim = find_claim(&["object_array", "field2"]);
    assert_eq!(object_array_field2_claim["mandatory"], true);
    assert_eq!(object_array_field2_claim["display"][0]["name"], "field2");

    // Check nested object array claims
    let nested_object_array_field1_claim =
        find_claim(&["address", "coordinates", "object_array", "field1"]);
    assert_eq!(nested_object_array_field1_claim["mandatory"], true);
    assert_eq!(
        nested_object_array_field1_claim["display"][0]["name"],
        "field1"
    );

    let nested_object_array_field2_claim =
        find_claim(&["address", "coordinates", "object_array", "field2"]);
    assert_eq!(nested_object_array_field2_claim["mandatory"], true);
    assert_eq!(
        nested_object_array_field2_claim["display"][0]["name"],
        "field2"
    );
}

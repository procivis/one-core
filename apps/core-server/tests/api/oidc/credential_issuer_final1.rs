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
        .create_with_nested_hell("test", &organisation, "NONE", Default::default())
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .openid_credential_issuer_final1(credential_schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    let issuer = format!(
        "{}/ssi/openid4vci/final-1.0/{}",
        context.config.app.core_base_url, credential_schema.id
    );

    assert_eq!(issuer, resp["credential_issuer"]);
    assert_eq!(format!("{issuer}/credential"), resp["credential_endpoint"]);
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
    assert_eq!(
        credentials[&credential_schema.schema_id]["wallet_storage_type"],
        "SOFTWARE"
    );
    assert_eq!(
        &credentials[&credential_schema.schema_id]["credential_definition"]["type"][0],
        "VerifiableCredential"
    );
    let subject =
        &credentials[&credential_schema.schema_id]["credential_definition"]["credentialSubject"];
    assert_expected_claims(subject);
}

fn assert_expected_claims(subject: &Value) {
    assert_eq!(subject["name"]["value_type"], "string");
    assert_eq!(subject["name"]["mandatory"], true);

    assert_eq!(subject["string_array"]["value_type"], "string[]");
    assert_eq!(subject["string_array"]["mandatory"], true);

    assert_eq!(subject["address"]["street"]["value_type"], "string");
    assert_eq!(subject["address"]["street"]["mandatory"], true);

    assert_eq!(
        subject["address"]["coordinates"]["string_array"]["value_type"],
        "string[]"
    );
    assert_eq!(
        subject["address"]["coordinates"]["string_array"]["mandatory"],
        true
    );
    assert_eq!(
        subject["address"]["coordinates"]["x"]["value_type"],
        "number"
    );
    assert_eq!(subject["address"]["coordinates"]["x"]["mandatory"], true);
    assert_eq!(
        subject["address"]["coordinates"]["y"]["value_type"],
        "number"
    );
    assert_eq!(subject["address"]["coordinates"]["y"]["mandatory"], true);

    assert_eq!(
        subject["address"]["coordinates"]["object_array"][0]["field1"]["value_type"],
        "string"
    );
    assert_eq!(
        subject["address"]["coordinates"]["object_array"][0]["field1"]["mandatory"],
        true
    );
    assert_eq!(
        subject["address"]["coordinates"]["object_array"][0]["field2"]["value_type"],
        "string"
    );
    assert_eq!(
        subject["address"]["coordinates"]["object_array"][0]["field2"]["mandatory"],
        true
    );

    assert_eq!(subject["object_array"][0]["field1"]["value_type"], "string");
    assert_eq!(subject["object_array"][0]["field1"]["mandatory"], true);
    assert_eq!(subject["object_array"][0]["field2"]["value_type"], "string");
    assert_eq!(subject["object_array"][0]["field2"]["mandatory"], true);
}

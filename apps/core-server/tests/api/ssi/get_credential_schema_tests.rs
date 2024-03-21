use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_credential_schema_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "credential-schema",
            &organisation,
            "LVVC",
            Default::default(),
        )
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_credential_schema(credential_schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&credential_schema.id);
    assert_eq!(resp["claims"].as_array().unwrap().len(), 1);
    assert_eq!(resp["revocationMethod"], "LVVC");
    assert_eq!(resp["organisationId"], organisation.id.to_string());
}

use uuid::Uuid;

use crate::utils::{context::TestContext, field_match::FieldHelpers};

#[tokio::test]
async fn test_get_json_ld_context_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let core_base_url = context.config.app.core_base_url;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test schema", &organisation, "NONE")
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_json_ld_context(credential_schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["@context"]["TestSchemaCredential"]["@id"].assert_eq(&format!(
        "{}/ssi/context/v1/{}#TestSchemaCredential",
        core_base_url, credential_schema.id
    ));
    resp["@context"]["TestSchemaSubject"]["@id"].assert_eq(&format!(
        "{}/ssi/context/v1/{}#TestSchemaSubject",
        core_base_url, credential_schema.id
    ));
    resp["@context"]["TestSchemaSubject"]["@context"]["firstName"].assert_eq(&format!(
        "{}/ssi/context/v1/{}#firstName",
        core_base_url, credential_schema.id
    ));
}

#[tokio::test]
async fn test_get_json_ld_context_not_found() {
    // GIVEN
    let context = TestContext::new().await;

    // WHEN
    let resp = context.api.ssi.get_json_ld_context(Uuid::new_v4()).await;

    // THEN
    assert_eq!(resp.status(), 404);
}

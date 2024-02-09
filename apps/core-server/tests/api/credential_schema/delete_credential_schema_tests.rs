use crate::utils::context::TestContext;

#[tokio::test]
async fn test_delete_credential_schema_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test schema", &organisation, "BITSTRINGSTATUSLIST")
        .await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .delete(&credential_schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let credential_schema = context
        .db
        .credential_schemas
        .get(&credential_schema.id)
        .await;
    assert!(credential_schema.deleted_at.is_some());
}

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_import_credential_schema_fails_deactivated_organisation() {
    // GIVEN
    let (context, organisation1) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "some credential schema",
            &organisation1,
            "NONE",
            Default::default(),
        )
        .await;

    let credential_schema = context
        .api
        .credential_schemas
        .get(&credential_schema.id)
        .await
        .json_value()
        .await;

    let organisation2 = context.db.organisations.create().await;
    context.db.organisations.deactivate(&organisation2.id).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .import(organisation2.id, credential_schema)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0241", resp.error_code().await);
}

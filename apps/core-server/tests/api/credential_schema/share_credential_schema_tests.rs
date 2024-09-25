use crate::utils::context::TestContext;

#[tokio::test]
async fn test_share_credential_schema_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test schema",
            &organisation,
            "BITSTRINGSTATUSLIST",
            Default::default(),
        )
        .await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .share(&credential_schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    assert_eq!(resp.json_value().await["url"], "CORE_URL");
}

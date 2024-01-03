use crate::utils::context::TestContext;

#[tokio::test]
async fn test_get_list_credential_schema_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    for i in 1..15 {
        context
            .db
            .credential_schemas
            .create(&format!("test-{}", i), &organisation, "NONE")
            .await;
    }

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .list(1, 8, &organisation.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalItems"], 14);
    assert_eq!(resp["totalPages"], 2);
    assert_eq!(resp["values"].as_array().unwrap().len(), 6);
}

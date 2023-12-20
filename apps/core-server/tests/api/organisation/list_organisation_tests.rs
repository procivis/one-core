use crate::utils::context::TestContext;

#[tokio::test]
async fn test_list_organisation_success() {
    // GIVEN
    let context = TestContext::new().await;

    for _ in 1..15 {
        context.db.create_organisation().await;
    }

    // WHEN
    let resp = context.api_client.list_organisations().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp.as_array().unwrap().len(), 14);
}

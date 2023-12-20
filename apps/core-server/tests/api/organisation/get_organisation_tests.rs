use crate::utils::{context::TestContext, field_match::FieldHelpers};

#[tokio::test]
async fn test_get_organisation_success() {
    // GIVEN
    let context = TestContext::new().await;
    let organisation = context.db.create_organisation().await;

    // WHEN
    let resp = context.api_client.get_organisation(organisation.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&organisation.id);
    assert!(resp["createdDate"].is_string());
    assert!(resp["lastModified"].is_string());
}

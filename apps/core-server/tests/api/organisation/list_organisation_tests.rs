use similar_asserts::assert_eq;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_list_organisation_success() {
    // GIVEN
    let context = TestContext::new(None).await;

    for _ in 1..15 {
        context.db.organisations.create().await;
    }

    // WHEN
    let resp = context.api.organisations.list().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp.as_array().unwrap().len(), 14);
    assert!(resp[0]["name"].is_string());
}

#[tokio::test]
async fn test_list_organisation_deactivated_success() {
    // GIVEN
    let context = TestContext::new(None).await;

    for _ in 1..15 {
        let organisation = context.db.organisations.create().await;
        context.db.organisations.deactivate(&organisation.id).await;
    }

    // WHEN
    let resp = context.api.organisations.list().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp.as_array().unwrap().len(), 14);
    assert!(resp[0]["name"].is_string());
    assert!(resp[0]["deactivatedAt"].is_string());
}

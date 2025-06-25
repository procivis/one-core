use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_organisation_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context.api.organisations.get(&organisation.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&organisation.id);
    resp["name"].assert_eq(&organisation.name);
    assert!(resp["createdDate"].is_string());
    assert!(resp["lastModified"].is_string());
}

#[tokio::test]
async fn get_deactivated_organisation_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    context.db.organisations.deactivate(&organisation.id).await;
    let resp = context.api.organisations.get(&organisation.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&organisation.id);
    resp["name"].assert_eq(&organisation.name);
    assert!(resp["createdDate"].is_string());
    assert!(resp["lastModified"].is_string());
    assert!(resp["deactivatedAt"].is_string());
}

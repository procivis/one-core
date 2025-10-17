use similar_asserts::assert_eq;

use crate::utils::api_clients::organisations::OrganisationFilters;
use crate::utils::context::TestContext;

#[tokio::test]
async fn test_list_organisation_success() {
    // GIVEN
    let context = TestContext::new(None).await;

    for _ in 1..15 {
        context.db.organisations.create().await;
    }

    // WHEN
    let resp = context
        .api
        .organisations
        .list(OrganisationFilters {
            page: 0,
            page_size: 1000,
            name: None,
            created_date_after: None,
            created_date_before: None,
            last_modified_after: None,
            last_modified_before: None,
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let values = resp["values"].as_array().unwrap();
    assert_eq!(values.len(), 14);
    assert!(values[0]["name"].is_string());
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
    let resp = context
        .api
        .organisations
        .list(OrganisationFilters {
            page: 0,
            page_size: 1000,
            name: None,
            created_date_after: None,
            created_date_before: None,
            last_modified_after: None,
            last_modified_before: None,
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let values = resp["values"].as_array().unwrap();
    assert_eq!(values.len(), 14);
    assert!(values[0]["name"].is_string());
    assert!(values[0]["deactivatedAt"].is_string());
}

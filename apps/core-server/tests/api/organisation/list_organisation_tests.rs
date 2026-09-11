use similar_asserts::assert_eq;

use crate::utils::api_clients::organisations::OrganisationFilters;
use crate::utils::context::TestContext;
use crate::utils::db_clients::organisations::TestingOrganisationParams;

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
            created_date_after: None,
            created_date_before: None,
            last_modified_after: None,
            last_modified_before: None,
            has_parent_organisation: None,
            parent_organisations: None,
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let values = resp["values"].as_array().unwrap();
    assert_eq!(values.len(), 14);
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
            created_date_after: None,
            created_date_before: None,
            last_modified_after: None,
            last_modified_before: None,
            has_parent_organisation: None,
            parent_organisations: None,
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let values = resp["values"].as_array().unwrap();
    assert_eq!(values.len(), 14);
    assert!(values[0]["deactivatedAt"].is_string());
}

#[tokio::test]
async fn test_list_organisation_filter_has_parent_organisation() {
    // GIVEN
    let context = TestContext::new(None).await;
    let parent = context.db.organisations.create().await;
    let child = context
        .db
        .organisations
        .create_with(TestingOrganisationParams {
            parent_organisation: Some(parent.id),
            ..Default::default()
        })
        .await;

    // WHEN - filter for organisations that have a parent
    let resp = context
        .api
        .organisations
        .list(OrganisationFilters {
            page: 0,
            page_size: 1000,
            created_date_after: None,
            created_date_before: None,
            last_modified_after: None,
            last_modified_before: None,
            has_parent_organisation: Some(true),
            parent_organisations: None,
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let values = resp["values"].as_array().unwrap();
    assert_eq!(values.len(), 1);
    assert_eq!(values[0]["id"].as_str().unwrap(), child.id.to_string());

    // WHEN - filter for root organisations
    let resp = context
        .api
        .organisations
        .list(OrganisationFilters {
            page: 0,
            page_size: 1000,
            created_date_after: None,
            created_date_before: None,
            last_modified_after: None,
            last_modified_before: None,
            has_parent_organisation: Some(false),
            parent_organisations: None,
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let values = resp["values"].as_array().unwrap();
    assert_eq!(values.len(), 1);
    assert_eq!(values[0]["id"].as_str().unwrap(), parent.id.to_string());
}

#[tokio::test]
async fn test_list_organisation_filter_parent_organisations() {
    // GIVEN
    let context = TestContext::new(None).await;
    let parent_a = context.db.organisations.create().await;
    let parent_b = context.db.organisations.create().await;
    let child_of_a = context
        .db
        .organisations
        .create_with(TestingOrganisationParams {
            parent_organisation: Some(parent_a.id),
            ..Default::default()
        })
        .await;
    let _child_of_b = context
        .db
        .organisations
        .create_with(TestingOrganisationParams {
            parent_organisation: Some(parent_b.id),
            ..Default::default()
        })
        .await;

    // WHEN
    let resp = context
        .api
        .organisations
        .list(OrganisationFilters {
            page: 0,
            page_size: 1000,
            created_date_after: None,
            created_date_before: None,
            last_modified_after: None,
            last_modified_before: None,
            has_parent_organisation: None,
            parent_organisations: Some(vec![parent_a.id]),
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let values = resp["values"].as_array().unwrap();
    assert_eq!(values.len(), 1);
    assert_eq!(values[0]["id"].as_str().unwrap(), child_of_a.id.to_string());
}

#[tokio::test]
async fn test_list_organisation_unknown_query_param() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context
        .api
        .client
        .get("/api/organisation/v1?page=1&pageSize=1&unknown=something")
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    let resp = resp.json_value().await;

    let code = resp["code"].as_str().unwrap();
    assert_eq!(code, "BR_0084",);

    let message = resp["cause"]["message"].as_str().unwrap();
    assert_eq!(
        message,
        "Query extraction error: Unknown query params: unknown"
    );
}

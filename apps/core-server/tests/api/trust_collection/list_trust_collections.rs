use similar_asserts::assert_eq;

use crate::utils::api_clients::trust_collections::ListFilters;
use crate::utils::context::TestContext;
use crate::utils::db_clients::trust_collections::TestTrustCollectionParams;

#[tokio::test]
async fn test_get_trust_collection_list() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    context
        .db
        .trust_collections
        .create(
            organisation.clone(),
            TestTrustCollectionParams {
                name: Some("test collection 1".to_string()),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .trust_collections
        .create(
            organisation.clone(),
            TestTrustCollectionParams {
                name: Some("test collection 2".to_string()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .trust_collections
        .list(
            0,
            ListFilters {
                organisation_id: Some(organisation.id),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body["totalItems"], 2);
    assert_eq!(body["values"].as_array().unwrap().len(), 2);
}

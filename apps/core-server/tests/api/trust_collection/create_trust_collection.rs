use similar_asserts::assert_eq;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_post_trust_collection() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .trust_collections
        .create("new collection", Some(organisation.id))
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let body = resp.json_value().await;
    assert!(body["id"].is_string());
}

#[tokio::test]
async fn test_post_trust_collection_already_exists() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    context
        .db
        .trust_collections
        .create("existing collection", organisation.clone(), None)
        .await;

    // WHEN
    let resp = context
        .api
        .trust_collections
        .create("existing collection", Some(organisation.id))
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0398", resp.error_code().await);
}

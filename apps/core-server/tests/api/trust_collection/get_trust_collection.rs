use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_get_trust_collection() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let tc = context
        .db
        .trust_collections
        .create(organisation, Default::default())
        .await;

    // WHEN
    let resp = context.api.trust_collections.get(tc.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body["id"], tc.id.to_string());
    assert_eq!(body["name"], tc.name);
}

#[tokio::test]
async fn test_get_trust_collection_not_found() {
    // GIVEN
    let context = TestContext::new(None).await;
    let random_id = Uuid::new_v4();

    // WHEN
    let resp = context.api.trust_collections.get(random_id).await;

    // THEN
    assert_eq!(resp.status(), 404);
}

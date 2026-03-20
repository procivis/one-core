use similar_asserts::assert_eq;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_delete_trust_collection() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let tc = context
        .db
        .trust_collections
        .create("test collection", organisation.clone(), None)
        .await;

    // WHEN
    let resp = context.api.trust_collections.delete(tc.id).await;

    // THEN
    assert_eq!(resp.status(), 204);

    let resp = context.api.trust_collections.get(tc.id).await;
    assert_eq!(resp.status(), 404);

    let history_entries = context.db.histories.get_by_entity_id(&tc.id.into()).await;
    let contains_history_entry = history_entries.values.iter().any(|entry| {
        entry.entity_type == one_core::model::history::HistoryEntityType::TrustCollection
            && entry.action == one_core::model::history::HistoryAction::Deleted
    });
    assert!(contains_history_entry);
}

#[tokio::test]
async fn test_delete_trust_collection_not_found() {
    // GIVEN
    let (context, _) = TestContext::new_with_organisation(None).await;
    let non_existent_id = uuid::Uuid::new_v4();

    // WHEN
    let resp = context.api.trust_collections.delete(non_existent_id).await;

    // THEN
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_delete_trust_collection_twice() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let tc = context
        .db
        .trust_collections
        .create("test collection", organisation.clone(), None)
        .await;

    // WHEN
    let resp1 = context.api.trust_collections.delete(tc.id).await;
    let resp2 = context.api.trust_collections.delete(tc.id).await;

    // THEN
    assert_eq!(resp1.status(), 204);
    assert_eq!(resp2.status(), 404);
}

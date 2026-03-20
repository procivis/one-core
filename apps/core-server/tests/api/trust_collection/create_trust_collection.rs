use shared_types::TrustCollectionId;
use similar_asserts::assert_eq;

use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

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
    let trust_collection_id_json = &resp.json_value().await["id"];
    let trust_collection_id = trust_collection_id_json.parse::<TrustCollectionId>();
    let history_entries = context
        .db
        .histories
        .get_by_entity_id(&trust_collection_id.into())
        .await;
    let contains_history_entry = history_entries.values.iter().any(|entry| {
        entry.entity_type == one_core::model::history::HistoryEntityType::TrustCollection
            && entry.action == one_core::model::history::HistoryAction::Created
    });
    assert!(contains_history_entry);
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

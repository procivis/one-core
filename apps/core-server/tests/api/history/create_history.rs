use one_core::model::history::{HistoryAction, HistoryEntityType, HistoryMetadata, HistorySource};
use serde_json::json;
use similar_asserts::assert_eq;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_create_history_without_metadata() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context
        .api
        .histories
        .create(
            HistorySource::Bff,
            HistoryEntityType::User,
            HistoryAction::Created,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    let id = resp["id"].as_str().unwrap();

    let entry = context.db.histories.get_entry(id.parse().unwrap()).await;
    assert_eq!(entry.source, HistorySource::Bff);
    assert_eq!(entry.entity_type, HistoryEntityType::User);
    assert_eq!(entry.action, HistoryAction::Created);
    assert!(entry.metadata.is_none());
}

#[tokio::test]
async fn test_create_history_with_metadata() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let metadata_value = json!({ "custom": "value" });
    let resp = context
        .api
        .histories
        .create(
            HistorySource::Bff,
            HistoryEntityType::User,
            HistoryAction::Created,
            Some(metadata_value.clone()),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    let id = resp["id"].as_str().unwrap();

    let entry = context.db.histories.get_entry(id.parse().unwrap()).await;
    assert_eq!(entry.source, HistorySource::Bff);
    assert_eq!(entry.entity_type, HistoryEntityType::User);
    assert_eq!(entry.action, HistoryAction::Created);
    let HistoryMetadata::External(value) = entry.metadata.unwrap() else {
        panic!("invalid metadata");
    };
    assert_eq!(value, metadata_value);
}

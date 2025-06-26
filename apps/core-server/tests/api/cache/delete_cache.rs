use one_core::model::remote_entity_cache::{CacheType, RemoteEntityCacheEntry};
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_delete_all_cache_entries() {
    // GIVEN
    let context = TestContext::new(None).await;

    let entry1 = test_entry(CacheType::JsonLdContext, false);
    context.db.remote_entities.add_entry(entry1.clone()).await;
    let entry2 = test_entry(CacheType::DidDocument, false);
    context.db.remote_entities.add_entry(entry2.clone()).await;
    let entry3 = test_entry(CacheType::JsonSchema, false);
    context.db.remote_entities.add_entry(entry3.clone()).await;

    // WHEN
    let resp = context.api.cache.delete(None::<Vec<String>>).await;
    assert_eq!(204, resp.status());

    // THEN
    assert_eq!(context.db.remote_entities.get(&entry1.id).await, None);
    assert_eq!(context.db.remote_entities.get(&entry2.id).await, None);
    assert_eq!(context.db.remote_entities.get(&entry3.id).await, None);
}

#[tokio::test]
async fn test_delete_cache_entries_with_type() {
    // GIVEN
    let context = TestContext::new(None).await;

    let entry1 = test_entry(CacheType::JsonLdContext, false);
    context.db.remote_entities.add_entry(entry1.clone()).await;
    let entry2 = test_entry(CacheType::DidDocument, false);
    context.db.remote_entities.add_entry(entry2.clone()).await;
    let entry3 = test_entry(CacheType::JsonSchema, false);
    context.db.remote_entities.add_entry(entry3.clone()).await;

    // WHEN
    let resp = context.api.cache.delete(Some(vec!["JSON_SCHEMA"])).await;
    assert_eq!(204, resp.status());

    // THEN
    assert_eq!(
        context.db.remote_entities.get(&entry1.id).await.unwrap(),
        entry1
    );
    assert_eq!(
        context.db.remote_entities.get(&entry2.id).await.unwrap(),
        entry2
    );
    assert_eq!(context.db.remote_entities.get(&entry3.id).await, None);
}

#[tokio::test]
async fn test_delete_cache_entries_multiple_types() {
    // GIVEN
    let context = TestContext::new(None).await;

    let entry1 = test_entry(CacheType::JsonLdContext, false);
    context.db.remote_entities.add_entry(entry1.clone()).await;
    let entry2 = test_entry(CacheType::DidDocument, false);
    context.db.remote_entities.add_entry(entry2.clone()).await;
    let entry3 = test_entry(CacheType::JsonSchema, false);
    context.db.remote_entities.add_entry(entry3.clone()).await;

    // WHEN
    let resp = context
        .api
        .cache
        .delete(Some(vec!["JSON_SCHEMA", "DID_DOCUMENT"]))
        .await;
    assert_eq!(204, resp.status());

    // THEN
    assert_eq!(
        context.db.remote_entities.get(&entry1.id).await.unwrap(),
        entry1
    );
    assert_eq!(context.db.remote_entities.get(&entry2.id).await, None);
    assert_eq!(context.db.remote_entities.get(&entry3.id).await, None);
}

#[tokio::test]
async fn test_invalid_type() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.cache.delete(Some(vec!["invalid"])).await;
    // THEN
    assert_eq!(400, resp.status());
}

fn test_entry(cache_type: CacheType, persistent: bool) -> RemoteEntityCacheEntry {
    // some dbs don't support nanosecond precision
    let now = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
    let id = Uuid::new_v4().into();

    RemoteEntityCacheEntry {
        id,
        created_date: now,
        last_modified: now,
        value: format!("some value for {id}").into_bytes(),
        key: format!("some key for {id}"),
        hit_counter: 0,
        r#type: cache_type,
        media_type: None,
        persistent,
    }
}

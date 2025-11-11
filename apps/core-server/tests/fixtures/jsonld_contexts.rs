use one_core::model::remote_entity_cache::{CacheType, RemoteEntityCacheEntry};
use time::OffsetDateTime;
use uuid::Uuid;

/// Creates a cache entry for the W3C Verifiable Credentials v2 context
///
/// This is useful for pre-populating the cache in tests to avoid hitting
/// rate limits when fetching from w3.org during credential verification.
pub fn credentials_v2_cache_entry() -> RemoteEntityCacheEntry {
    let context = include_str!("../../../../lib/one-core/src/util/context_vc2_0.jsonld");
    let value = context.as_bytes().to_vec();
    let now = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
    RemoteEntityCacheEntry {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        last_used: now,
        expiration_date: Some(now + time::Duration::days(30)),
        key: "https://www.w3.org/ns/credentials/v2".to_string(),
        value,
        r#type: CacheType::JsonLdContext,
        media_type: Some("application/ld+json".to_string()),
    }
}

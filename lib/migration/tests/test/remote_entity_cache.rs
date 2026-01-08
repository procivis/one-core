use crate::fixtures::{ColumnType, fetch_schema};

#[tokio::test]
async fn test_db_schema_remote_entity_cache() {
    let schema = fetch_schema().await;

    let remote_entity_cache = schema
        .table("remote_entity_cache")
        .columns(&[
            "id",
            "created_date",
            "last_modified",
            "value",
            "key",
            "media_type",
            "expiration_date",
            "last_used",
            "type",
        ])
        .index("index-RemoteEntityCache-Key-Unique", true, &["key"])
        .index(
            "index-RemoteEntityCache-Type-ExpirationDate",
            false,
            &["type", "expiration_date"],
        );
    remote_entity_cache
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    remote_entity_cache
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    remote_entity_cache
        .column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    remote_entity_cache
        .column("value")
        .r#type(ColumnType::Blob)
        .nullable(false)
        .default(None);
    remote_entity_cache
        .column("key")
        .r#type(ColumnType::String(Some(4096)))
        .nullable(false)
        .default(None);
    remote_entity_cache
        .column("media_type")
        .r#type(ColumnType::String(None))
        .nullable(true);
    remote_entity_cache
        .column("expiration_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(true);
    remote_entity_cache
        .column("last_used")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    remote_entity_cache
        .column("type")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
}

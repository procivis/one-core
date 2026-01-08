use crate::fixtures::{ColumnType, fetch_schema};

#[tokio::test]
async fn test_db_schema_blob_storage() {
    let schema = fetch_schema().await;

    let blob_storage = schema.table("blob_storage").columns(&[
        "id",
        "created_date",
        "last_modified",
        "value",
        "type",
    ]);
    blob_storage
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    blob_storage
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    blob_storage
        .column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    blob_storage
        .column("value")
        .r#type(ColumnType::Blob)
        .nullable(false)
        .default(None);
    blob_storage
        .column("type")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
}

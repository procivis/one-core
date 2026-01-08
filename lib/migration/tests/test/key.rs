use sea_orm::DbBackend;

use crate::fixtures::{ColumnType, fetch_schema};

#[tokio::test]
async fn test_db_schema_key() {
    let schema = fetch_schema().await;

    let mut columns = vec![
        "id",
        "created_date",
        "last_modified",
        "name",
        "public_key",
        "key_reference",
        "storage_type",
        "key_type",
        "organisation_id",
        "deleted_at",
    ];
    if schema.backend() == DbBackend::MySql {
        columns.extend(["deleted_at_materialized"]);
    }

    let key = schema
        .table("key")
        .columns(&columns)
        .index(
            "index_Key_Name-OrganisationId-DeletedAt_Unique",
            true,
            &["name", "organisation_id", "deleted_at_materialized"],
        )
        .index("index-Key-CreatedDate", false, &["created_date"]);
    key.column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    key.column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    key.column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    key.column("name")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    key.column("public_key")
        .r#type(ColumnType::Blob)
        .nullable(false)
        .default(None);
    key.column("key_reference")
        .r#type(ColumnType::Blob)
        .nullable(true);
    key.column("storage_type")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    key.column("key_type")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    key.column("organisation_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .foreign_key("fk-Key-OrganisationId", "organisation", "id");
    key.column("deleted_at")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(true);
}

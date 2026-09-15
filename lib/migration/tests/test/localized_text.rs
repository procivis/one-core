use crate::fixtures::{ColumnType, get_schema};

#[tokio::test]
async fn test_db_schema_localized_text() {
    let schema = get_schema().await;

    let localized_text = schema
        .table("localized_text")
        .columns(&[
            "entity_id",
            "field",
            "lang",
            "created_date",
            "last_modified",
            "value",
            "entity_type",
        ])
        .index(
            "index-LocalizedText-EntityType-Field-Lang-Value",
            false,
            &["entity_type", "field", "lang", "value"],
        );
    localized_text
        .column("entity_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    localized_text
        .column("field")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None)
        .primary_key();
    localized_text
        .column("lang")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None)
        .primary_key();
    localized_text
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    localized_text
        .column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    localized_text
        .column("value")
        .r#type(ColumnType::Text)
        .nullable(false)
        .default(None);
    localized_text
        .column("entity_type")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
}

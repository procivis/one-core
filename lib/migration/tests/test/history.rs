use crate::fixtures::{ColumnType, get_schema};

#[tokio::test]
async fn test_db_schema_history() {
    let schema = get_schema().await;

    let history = schema
        .table("history")
        .columns(&[
            "id",
            "created_date",
            "action",
            "entity_id",
            "entity_type",
            "organisation_id",
            "metadata",
            "name",
            "target",
            "user",
            "source",
        ])
        .index("index-History-EntityId", false, &["entity_id"])
        .index("index-History-Metadata", false, &["metadata"])
        .index("index-History-CreatedDate", false, &["created_date"])
        .index(
            "index-History-Org-CreatedDate",
            false,
            &["organisation_id", "created_date"],
        );
    history
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    history
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    history
        .column("action")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    history
        .column("entity_id")
        .r#type(ColumnType::Uuid)
        .nullable(true);
    history
        .column("entity_type")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    history
        .column("organisation_id")
        .r#type(ColumnType::Uuid)
        .nullable(true)
        .foreign_key("fk-History-OrganisationId-new", "organisation", "id");
    history
        .column("metadata")
        .r#type(ColumnType::String(None))
        .nullable(true);
    history
        .column("name")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    history
        .column("target")
        .r#type(ColumnType::String(None))
        .nullable(true);
    history
        .column("user")
        .r#type(ColumnType::String(None))
        .nullable(true);
    history
        .column("source")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
}

use sea_orm::DbBackend;

use crate::fixtures::{ColumnType, get_schema};

#[tokio::test]
async fn test_db_schema_identifier() {
    let schema = get_schema().await;

    let mut columns = vec![
        "id",
        "created_date",
        "last_modified",
        "name",
        "type",
        "is_remote",
        "state",
        "organisation_id",
        "did_id",
        "key_id",
        "deleted_at",
    ];
    if schema.backend() == DbBackend::MySql {
        columns.extend(["deleted_at_materialized"]);
    }

    let identifier = schema.table("identifier").columns(&columns).index(
        "index_Identifier_Name-OrganisationId-DeletedAt_Unique",
        true,
        &["name", "organisation_id", "deleted_at_materialized"],
    );
    identifier
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    identifier
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    identifier
        .column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    identifier
        .column("name")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    identifier
        .column("type")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    identifier
        .column("is_remote")
        .r#type(ColumnType::Boolean)
        .nullable(false)
        .default(None);
    identifier
        .column("state")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    identifier
        .column("organisation_id")
        .r#type(ColumnType::Uuid)
        .nullable(true)
        .foreign_key("fk_identifier_organisation", "organisation", "id");
    identifier
        .column("did_id")
        .r#type(ColumnType::Uuid)
        .nullable(true)
        .foreign_key("fk_identifier_did", "did", "id");
    identifier
        .column("key_id")
        .r#type(ColumnType::Uuid)
        .nullable(true)
        .foreign_key("fk_identifier_key", "key", "id");
    identifier
        .column("deleted_at")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(true);
}

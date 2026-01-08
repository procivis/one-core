use sea_orm::DbBackend;

use crate::fixtures::{ColumnType, get_schema};

#[tokio::test]
async fn test_db_schema_did() {
    let schema = get_schema().await;

    let mut columns = vec![
        "id",
        "created_date",
        "last_modified",
        "did",
        "name",
        "type",
        "method",
        "organisation_id",
        "deactivated",
        "deleted_at",
        "log",
    ];
    if schema.backend() == DbBackend::MySql {
        columns.extend(["deleted_at_materialized", "organisation_id_materialized"]);
    }

    let did = schema
        .table("did")
        .columns(&columns)
        .index(
            "index_Did_Name-OrganisationId-DeletedAt_Unique",
            true,
            &["name", "organisation_id", "deleted_at_materialized"],
        )
        .index(
            "index-Did-Did-OrganisationId-Unique",
            true,
            &["did", "organisation_id_materialized"],
        )
        .index("index-Did-CreatedDate", false, &["created_date"])
        .index("index-Did-Did", false, &["did"]);
    did.column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    did.column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    did.column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    did.column("did")
        .r#type(ColumnType::String(Some(4000)))
        .nullable(false)
        .default(None);
    did.column("name")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    did.column("type")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    did.column("method")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    did.column("organisation_id")
        .r#type(ColumnType::Uuid)
        .nullable(true)
        .foreign_key("fk-Did-OrganisationId", "organisation", "id");
    did.column("deactivated")
        .r#type(ColumnType::Boolean)
        .nullable(false)
        .default(None);
    did.column("deleted_at")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(true);
    did.column("log").r#type(ColumnType::Text).nullable(true);
}

#[tokio::test]
async fn test_db_schema_key_did() {
    let schema = get_schema().await;

    let key_did = schema
        .table("key_did")
        .columns(&["did_id", "key_id", "role", "reference"]);
    key_did
        .column("did_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key()
        .foreign_key("fk-KeyDid-DidId", "did", "id");
    key_did
        .column("key_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key()
        .foreign_key("fk-KeyDid-KeyId", "key", "id");
    key_did
        .column("role")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None)
        .primary_key();
    key_did
        .column("reference")
        .r#type(ColumnType::String(Some(4000)))
        .nullable(false)
        .default(None);
}

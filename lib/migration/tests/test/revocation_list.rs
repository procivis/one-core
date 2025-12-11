use crate::fixtures::{ColumnType, fetch_schema};

#[tokio::test]
async fn test_db_schema_revocation_list() {
    let schema = fetch_schema().await;

    let revocation_list = schema
        .table("revocation_list")
        .columns(&[
            "id",
            "created_date",
            "last_modified",
            "credentials",
            "purpose",
            "format",
            "type",
            "issuer_identifier_id",
        ])
        .index(
            "index-IssuerIdentifierId-Purpose-Type-Unique",
            true,
            &["issuer_identifier_id", "purpose", "type"],
        );
    revocation_list
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    revocation_list
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    revocation_list
        .column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    revocation_list
        .column("credentials")
        .r#type(ColumnType::Blob)
        .nullable(false)
        .default(None);
    revocation_list
        .column("purpose")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    revocation_list
        .column("format")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    revocation_list
        .column("type")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    revocation_list
        .column("issuer_identifier_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key(
            "fk_revocation_list_issuer_identifier_id",
            "identifier",
            "id",
        );
}

#[tokio::test]
async fn test_db_schema_revocation_list_entry() {
    let schema = fetch_schema().await;

    let revocation_list_entry = schema
        .table("revocation_list_entry")
        .columns(&[
            "id",
            "created_date",
            "revocation_list_id",
            "index",
            "credential_id",
            "status",
            "type",
        ])
        .index(
            "index-RevocationList-Index-Unique",
            true,
            &["revocation_list_id", "index"],
        );
    revocation_list_entry
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    revocation_list_entry
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    revocation_list_entry
        .column("revocation_list_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key(
            "fk-RevocationListEntry-RevocationListId",
            "revocation_list",
            "id",
        );
    revocation_list_entry
        .column("index")
        .r#type(ColumnType::Unsigned)
        .nullable(false)
        .default(None);
    revocation_list_entry
        .column("credential_id")
        .r#type(ColumnType::Uuid)
        .nullable(true)
        .foreign_key("fk-RevocationListEntry-CredentialId", "credential", "id");
    revocation_list_entry
        .column("status")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    revocation_list_entry
        .column("type")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
}

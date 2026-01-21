use sea_orm::DbBackend;

use crate::fixtures::{ColumnType, get_schema};

#[tokio::test]
async fn test_db_schema_revocation_list() {
    let schema = get_schema().await;

    let mut columns = vec![
        "id",
        "created_date",
        "last_modified",
        "formatted_list",
        "purpose",
        "format",
        "type",
        "issuer_identifier_id",
        "issuer_certificate_id",
    ];
    if schema.backend() == DbBackend::MySql {
        columns.extend(["issuer_certificate_id_materialized"]);
    }

    let revocation_list = schema.table("revocation_list").columns(&columns).index(
        "index-IssuerIdentifierId-IssuerCertificateId-Purpose-Type-Unique",
        true,
        &[
            "issuer_identifier_id",
            "issuer_certificate_id_materialized",
            "purpose",
            "type",
        ],
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
        .column("formatted_list")
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
    revocation_list
        .column("issuer_certificate_id")
        .r#type(if schema.backend() == DbBackend::MySql {
            ColumnType::String(Some(36))
        } else {
            ColumnType::Uuid
        })
        .nullable(true)
        .foreign_key(
            "fk_revocation_list_issuer_certificate_id",
            "certificate",
            "id",
        );
}

#[tokio::test]
async fn test_db_schema_revocation_list_entry() {
    let schema = get_schema().await;

    let revocation_list_entry = schema
        .table("revocation_list_entry")
        .columns(&[
            "id",
            "created_date",
            "last_modified",
            "revocation_list_id",
            "index",
            "credential_id",
            "status",
            "type",
            "signature_type",
            "serial",
        ])
        .index(
            "index-RevocationList-Index-Unique",
            true,
            &["revocation_list_id", "index"],
        )
        .index(
            "index-RevocationList-Serial-Unique",
            true,
            &["revocation_list_id", "serial"],
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
        .column("last_modified")
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
        .nullable(true);
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
    revocation_list_entry
        .column("signature_type")
        .r#type(ColumnType::String(None))
        .nullable(true);
    revocation_list_entry
        .column("serial")
        .r#type(ColumnType::VarBinary(Some(20)))
        .nullable(true);
}

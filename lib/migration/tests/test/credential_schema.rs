use sea_orm::DbBackend;

use crate::fixtures::{ColumnType, get_schema};

#[tokio::test]
async fn test_db_schema_credential_schema() {
    let schema = get_schema().await;

    let mut columns = vec![
        "id",
        "created_date",
        "last_modified",
        "deleted_at",
        "name",
        "organisation_id",
        "layout_properties",
        "imported_source_url",
        "allow_suspension",
        "requires_wallet_instance_attestation",
        "key_storage_security",
        "transaction_code_type",
        "transaction_code_length",
        "transaction_code_description",
        "batch_size",
        "allow_revocation",
        "embedded_disclosure_policy",
        "ecosystem",
        "expiration",
        "preferred_key_storage_attestation_lifetime",
        "preferred_instance_attestation_lifetime",
    ];
    if schema.backend() == DbBackend::MySql {
        columns.push("deleted_at_materialized");
    }

    let mut index_name_unique_columns = vec!["name", "organisation_id"];
    if schema.backend() == DbBackend::MySql {
        index_name_unique_columns.push("deleted_at_materialized")
    } else {
        index_name_unique_columns.push("deleted_at")
    }
    let credential_schema = schema
        .table("credential_schema")
        .columns(&columns)
        .index(
            "index_CredentialSchema_Name-OrganisationId-DeletedAt_Unique",
            true,
            &index_name_unique_columns,
        )
        .index(
            "index-CredentialSchema-CreatedDate",
            false,
            &["created_date"],
        )
        .index(
            "index-CredentialSchema-OrganisationId-DeletedAt-CreatedDate",
            false,
            &["organisation_id", "deleted_at", "created_date"],
        );
    credential_schema
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    credential_schema
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    credential_schema
        .column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    credential_schema
        .column("deleted_at")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(true);
    credential_schema
        .column("name")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    credential_schema
        .column("organisation_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key("fk-CredentialSchema-OrganisationId", "organisation", "id");
    credential_schema
        .column("layout_properties")
        .r#type(ColumnType::JsonBinary)
        .nullable(true);
    credential_schema
        .column("imported_source_url")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    credential_schema
        .column("allow_suspension")
        .r#type(ColumnType::Boolean)
        .nullable(false)
        .default(None);
    credential_schema
        .column("requires_wallet_instance_attestation")
        .r#type(ColumnType::Boolean)
        .nullable(false)
        .default(None);
    credential_schema
        .column("key_storage_security")
        .r#type(ColumnType::String(None))
        .nullable(true);
    credential_schema
        .column("transaction_code_type")
        .r#type(ColumnType::String(None))
        .nullable(true);
    credential_schema
        .column("transaction_code_length")
        .r#type(ColumnType::Integer)
        .nullable(true);
    credential_schema
        .column("transaction_code_description")
        .r#type(ColumnType::String(Some(300)))
        .nullable(true);
    credential_schema
        .column("batch_size")
        .r#type(ColumnType::Integer)
        .nullable(true);
    credential_schema
        .column("allow_revocation")
        .r#type(ColumnType::Boolean)
        .nullable(false)
        .default(None);
    credential_schema
        .column("embedded_disclosure_policy")
        .r#type(ColumnType::Text)
        .nullable(true);
    credential_schema
        .column("ecosystem")
        .r#type(ColumnType::String(None))
        .nullable(true);
    credential_schema
        .column("expiration")
        .r#type(ColumnType::Integer)
        .nullable(true);
    credential_schema
        .column("preferred_key_storage_attestation_lifetime")
        .r#type(ColumnType::Integer)
        .nullable(true);
    credential_schema
        .column("preferred_instance_attestation_lifetime")
        .r#type(ColumnType::Integer)
        .nullable(true);
}

#[tokio::test]
async fn test_db_schema_claim_schema() {
    let schema = get_schema().await;

    let claim_schema = schema
        .table("claim_schema")
        .columns(&[
            "id",
            "created_date",
            "last_modified",
            "key",
            "datatype",
            "array",
            "metadata",
            "credential_schema_id",
            "required",
            "order",
        ])
        .index(
            "index-ClaimSchema-Key-CredentialSchemaId-Unique",
            true,
            &["key", "credential_schema_id"],
        )
        .index(
            "index-ClaimSchema-Order-CredentialSchemaId-Unique",
            true,
            &["order", "credential_schema_id"],
        );
    claim_schema
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    claim_schema
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    claim_schema
        .column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    claim_schema
        .column("key")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    claim_schema
        .column("datatype")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    claim_schema
        .column("array")
        .r#type(ColumnType::Boolean)
        .nullable(false)
        .default(None);
    claim_schema
        .column("metadata")
        .r#type(ColumnType::Boolean)
        .nullable(false)
        .default(None);
    claim_schema
        .column("credential_schema_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key(
            "fk_claim_schema_credential_schema_id",
            "credential_schema",
            "id",
        );
    claim_schema
        .column("required")
        .r#type(ColumnType::Boolean)
        .nullable(false)
        .default(None);
    claim_schema
        .column("order")
        .r#type(ColumnType::Integer)
        .nullable(false)
        .default(None);
}

#[tokio::test]
async fn test_db_schema_credential_schema_format() {
    let schema = get_schema().await;

    let columns = vec![
        "id",
        "created_date",
        "last_modified",
        "credential_schema_id",
        "format",
        "ecosystem_schema_id",
    ];

    let credential_schema_format = schema
        .table("credential_schema_format")
        .columns(&columns)
        .index(
            "index-CredentialSchemaFormat-CredentialSchemaId-Format_Unique",
            true,
            &["credential_schema_id", "format"],
        )
        .index(
            "index-CredentialSchemaFormat-CredentialSchemaId-ESchemaId_Unique",
            true,
            &["credential_schema_id", "ecosystem_schema_id"],
        )
        .index(
            "index-CredentialSchemaFormat-ESchemaId-Format-CredentialSchemaId",
            false,
            &["ecosystem_schema_id", "format", "credential_schema_id"],
        );
    credential_schema_format
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    credential_schema_format
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    credential_schema_format
        .column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    credential_schema_format
        .column("credential_schema_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key(
            "fk-CredentialSchemaFormat-CredentialSchemaId",
            "credential_schema",
            "id",
        );
    credential_schema_format
        .column("format")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    credential_schema_format
        .column("ecosystem_schema_id")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
}

#[tokio::test]
async fn test_db_schema_credential_schema_format_claim_schema() {
    let schema = get_schema().await;

    let mut columns = vec![
        "id",
        "created_date",
        "last_modified",
        "credential_schema_format_id",
        "claim_schema_id",
        "technical_key",
        "namespace",
    ];
    if schema.backend() == DbBackend::MySql {
        columns.push("namespace_materialized");
    }

    let mut technical_key_index_columns = vec!["technical_key", "credential_schema_format_id"];
    if schema.backend() == DbBackend::MySql {
        technical_key_index_columns.push("namespace_materialized")
    } else {
        technical_key_index_columns.push("namespace")
    }

    let cs_format_claim = schema
        .table("credential_schema_format_claim_schema")
        .columns(&columns)
        .index(
            "index-FormatClaimSchema-FormatId-ClaimSchemaId_Unique",
            true,
            &["credential_schema_format_id", "claim_schema_id"],
        )
        .index(
            "index-FormatClaimSchema-TechKey-FormatId-Namespace-Unique",
            true,
            &technical_key_index_columns,
        );
    cs_format_claim
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    cs_format_claim
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    cs_format_claim
        .column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    cs_format_claim
        .column("credential_schema_format_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key(
            "fk-CredentialSchemaFormatClaimSchema-CredentialSchemaFormatId",
            "credential_schema_format",
            "id",
        );
    cs_format_claim
        .column("claim_schema_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key(
            "fk-CredentialSchemaFormatClaimSchema-ClaimSchemaId",
            "claim_schema",
            "id",
        );
    cs_format_claim
        .column("technical_key")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    cs_format_claim
        .column("namespace")
        .r#type(ColumnType::String(None))
        .nullable(true);
}

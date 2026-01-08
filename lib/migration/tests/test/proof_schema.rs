use sea_orm::DbBackend;

use crate::fixtures::{ColumnType, fetch_schema};

#[tokio::test]
async fn test_db_schema_proof_schema() {
    let schema = fetch_schema().await;

    let mut columns = vec![
        "id",
        "created_date",
        "last_modified",
        "deleted_at",
        "name",
        "expire_duration",
        "organisation_id",
        "imported_source_url",
    ];
    if schema.backend() == DbBackend::MySql {
        columns.push("deleted_at_materialized");
    }

    let proof_schema = schema
        .table("proof_schema")
        .columns(&columns)
        .index(
            "index_ProofSchema_Name-OrganisationId-DeletedAt_Unique",
            true,
            &["name", "organisation_id", "deleted_at_materialized"],
        )
        .index("index-ProofSchema-CreatedDate", false, &["created_date"]);
    proof_schema
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    proof_schema
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    proof_schema
        .column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    proof_schema
        .column("deleted_at")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(true);
    proof_schema
        .column("name")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    proof_schema
        .column("expire_duration")
        .r#type(ColumnType::Unsigned)
        .nullable(false)
        .default(None);
    proof_schema
        .column("organisation_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key("fk-ProofSchema-OrganisationId", "organisation", "id");
    proof_schema
        .column("imported_source_url")
        .r#type(ColumnType::Text)
        .nullable(true);
}

#[tokio::test]
async fn test_db_schema_proof_input_schema() {
    let schema = fetch_schema().await;

    let proof_input_schema = schema.table("proof_input_schema").columns(&[
        "id",
        "created_date",
        "last_modified",
        "order",
        "validity_constraint",
        "credential_schema",
        "proof_schema",
    ]);
    proof_input_schema
        .column("id")
        .r#type(ColumnType::BigInt)
        .nullable(false)
        .default(None)
        .primary_key();
    proof_input_schema
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    proof_input_schema
        .column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    proof_input_schema
        .column("order")
        .r#type(ColumnType::Unsigned)
        .nullable(false)
        .default(None);
    proof_input_schema
        .column("validity_constraint")
        .r#type(ColumnType::BigInt)
        .nullable(true);
    proof_input_schema
        .column("credential_schema")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key(
            "fk-ProofInputSchema-CredentialSchema",
            "credential_schema",
            "id",
        );
    proof_input_schema
        .column("proof_schema")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key("fk-ProofInputSchema-ProofSchema", "proof_schema", "id");
}

#[tokio::test]
async fn test_db_schema_proof_input_claim_schema() {
    let schema = fetch_schema().await;

    let proof_input_claim_schema = schema.table("proof_input_claim_schema").columns(&[
        "claim_schema_id",
        "proof_input_schema_id",
        "order",
        "required",
    ]);
    proof_input_claim_schema
        .column("claim_schema_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key()
        .foreign_key(
            "fk-ProofInputClaimSchema-ClaimSchemaId",
            "claim_schema",
            "id",
        );
    proof_input_claim_schema
        .column("proof_input_schema_id")
        .r#type(ColumnType::BigInt)
        .nullable(false)
        .default(None)
        .primary_key()
        .foreign_key(
            "fk-ProofInputClaimSchema-ProofSchemaId",
            "proof_input_schema",
            "id",
        );
    proof_input_claim_schema
        .column("order")
        .r#type(ColumnType::Unsigned)
        .nullable(false)
        .default(None);
    proof_input_claim_schema
        .column("required")
        .r#type(ColumnType::Boolean)
        .nullable(false)
        .default(None);
}

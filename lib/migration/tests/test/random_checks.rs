use crate::fixtures::{ColumnType, DefaultValue, fetch_schema};

// Simplified test for various constraints and data-types until further detailed tests are implemented.
#[tokio::test]
async fn test_db_schema_random_checks() {
    let schema = fetch_schema().await;

    let credential_schema = schema
        .table("credential_schema")
        .index(
            "index-Organisation-SchemaId-DeletedAt_Unique",
            true,
            &["organisation_id", "schema_id", "deleted_at_materialized"],
        )
        .index(
            "index_CredentialSchema_Name-OrganisationId-DeletedAt_Unique",
            true,
            &["name", "organisation_id", "deleted_at_materialized"],
        );
    credential_schema
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();

    let claim_schema = schema.table("claim_schema");
    claim_schema
        .column("order")
        .r#type(ColumnType::Unsigned)
        .default(Some(DefaultValue::Integer(0)));

    let did = schema.table("did");
    did.column("did").r#type(ColumnType::String(Some(4000)));
    did.column("deactivated").r#type(ColumnType::Boolean);
    did.column("method").r#type(ColumnType::String(None));

    let certificate = schema
        .table("certificate")
        .index(
            "index-Certificate-Fingerprint-OrganisationId-Unique",
            true,
            &["fingerprint", "organisation_id"],
        )
        .index(
            "index-Certificate-Name-ExpiryDate-IdentifierId-Unique",
            true,
            &["name", "expiry_date", "identifier_id"],
        );
    certificate
        .column("expiry_date")
        .r#type(ColumnType::TimestampSeconds)
        .nullable(false)
        .default(None);

    let history = schema.table("history");
    history
        .column("source")
        .r#type(ColumnType::String(None))
        .default(Some(DefaultValue::String("CORE".to_string())));
}

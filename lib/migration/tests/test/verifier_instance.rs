use crate::fixtures::{ColumnType, get_schema};

#[tokio::test]
async fn test_db_schema_verifier_instance() {
    let schema = get_schema().await;

    let verifier_instance = schema
        .table("verifier_instance")
        .columns(&[
            "id",
            "created_date",
            "last_modified",
            "organisation_id",
            "provider_name",
            "provider_type",
            "provider_url",
        ])
        .index(
            "index-VerifierInstance-OrganisationId-Unique",
            true,
            &["organisation_id"],
        );
    verifier_instance
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    verifier_instance
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    verifier_instance
        .column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    verifier_instance
        .column("organisation_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key("fk-VerifierInstance-Organisation", "organisation", "id");
    verifier_instance
        .column("provider_name")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    verifier_instance
        .column("provider_type")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    verifier_instance
        .column("provider_url")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
}

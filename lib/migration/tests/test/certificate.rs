use crate::fixtures::{ColumnType, fetch_schema};

#[tokio::test]
async fn test_db_schema_certificate() {
    let schema = fetch_schema().await;

    let certificate = schema
        .table("certificate")
        .columns(&[
            "id",
            "created_date",
            "last_modified",
            "expiry_date",
            "identifier_id",
            "name",
            "chain",
            "state",
            "key_id",
            "fingerprint",
            "organisation_id",
        ])
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
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    certificate
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    certificate
        .column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    certificate
        .column("expiry_date")
        .r#type(ColumnType::TimestampSeconds)
        .nullable(false)
        .default(None);
    certificate
        .column("identifier_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key("fk_certificate_identifier", "identifier", "id");
    certificate
        .column("name")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    certificate
        .column("chain")
        .r#type(ColumnType::Text)
        .nullable(false)
        .default(None);
    certificate
        .column("state")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    certificate
        .column("key_id")
        .r#type(ColumnType::Uuid)
        .nullable(true)
        .foreign_key("fk_certificate_key", "key", "id");
    certificate
        .column("fingerprint")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    certificate
        .column("organisation_id")
        .r#type(ColumnType::Uuid)
        .nullable(true)
        .foreign_key("fk_certificate_organisation_id", "organisation", "id");
}

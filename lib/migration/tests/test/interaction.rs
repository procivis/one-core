use crate::fixtures::{ColumnType, get_schema};

#[tokio::test]
async fn test_db_schema_interaction() {
    let schema = get_schema().await;

    let interaction = schema
        .table("interaction")
        .columns(&[
            "id",
            "created_date",
            "last_modified",
            "data",
            "organisation_id",
            "nonce_id",
            "interaction_type",
            "expires_at",
        ])
        .index("index-Interaction-NonceId-Unique", true, &["nonce_id"])
        .index("index-Interaction-ExpiresAt", false, &["expires_at"]);
    interaction
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    interaction
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    interaction
        .column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    interaction
        .column("data")
        .r#type(ColumnType::Blob)
        .nullable(true);
    interaction
        .column("organisation_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key("fk-interaction-OrganisationId", "organisation", "id");
    interaction
        .column("nonce_id")
        .r#type(ColumnType::Uuid)
        .nullable(true);
    interaction
        .column("interaction_type")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    interaction
        .column("expires_at")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(true);
}

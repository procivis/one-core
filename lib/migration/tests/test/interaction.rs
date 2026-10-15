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
            "interaction_type",
            "expires_at",
            "ecosystem",
            "ecosystem_data",
            "dpop_key_id",
        ])
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
        .column("interaction_type")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    interaction
        .column("expires_at")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(true);
    interaction
        .column("ecosystem")
        .r#type(ColumnType::String(None))
        .nullable(true);
    interaction
        .column("ecosystem_data")
        .r#type(ColumnType::Blob)
        .nullable(true);
    interaction
        .column("dpop_key_id")
        .r#type(ColumnType::Uuid)
        .nullable(true)
        .foreign_key("fk-Interaction-DpopKeyId", "key", "id");
}

#[tokio::test]
async fn test_db_schema_used_nonce() {
    let schema = get_schema().await;

    let used_nonce = schema
        .table("used_nonce")
        .columns(&["id", "created_date", "interaction_id"]);
    used_nonce
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    used_nonce
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    used_nonce
        .column("interaction_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key("fk-UsedNonce-InteractionId", "interaction", "id");
}

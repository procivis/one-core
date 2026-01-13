use sea_orm::DbBackend;

use crate::fixtures::{ColumnType, get_schema};

#[tokio::test]
async fn test_db_schema_trust_anchor() {
    let schema = get_schema().await;

    let trust_anchor = schema
        .table("trust_anchor")
        .columns(&[
            "id",
            "created_date",
            "last_modified",
            "name",
            "type",
            "is_publisher",
            "publisher_reference",
        ])
        .index("UK-TrustAnchor-Name", true, &["name"]);
    trust_anchor
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    trust_anchor
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    trust_anchor
        .column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    trust_anchor
        .column("name")
        .r#type(ColumnType::Text)
        .nullable(false)
        .default(None);
    trust_anchor
        .column("type")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    trust_anchor
        .column("is_publisher")
        .r#type(ColumnType::Boolean)
        .nullable(false)
        .default(None);
    trust_anchor
        .column("publisher_reference")
        .r#type(ColumnType::Text)
        .nullable(false)
        .default(None);
}

#[tokio::test]
async fn test_db_schema_trust_entity() {
    let schema = get_schema().await;

    let mut columns = vec![
        "id",
        "created_date",
        "last_modified",
        "name",
        "logo",
        "website",
        "terms_url",
        "privacy_url",
        "role",
        "state",
        "trust_anchor_id",
        "organisation_id",
        "type",
        "entity_key",
        "content",
        "deactivated_at",
    ];
    if schema.backend() == DbBackend::MySql {
        columns.extend(["deactivated_at_materialized"]);
    }

    let trust_entity = schema
        .table("trust_entity")
        .columns(&columns)
        .index(
            "idx-TrustEntity-Name-OrganisationId-DeactivatedAt-Unique",
            true,
            &["name", "organisation_id", "deactivated_at_materialized"],
        )
        .index(
            "idx-TrustEntity-EntityKey-AnchorId-DeactivatedAt-Unique",
            true,
            &[
                "entity_key",
                "trust_anchor_id",
                "deactivated_at_materialized",
            ],
        );
    trust_entity
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    trust_entity
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    trust_entity
        .column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    trust_entity
        .column("name")
        .r#type(ColumnType::Text)
        .nullable(false)
        .default(None);
    trust_entity
        .column("logo")
        .r#type(ColumnType::Blob)
        .nullable(true);
    trust_entity
        .column("website")
        .r#type(ColumnType::Text)
        .nullable(true);
    trust_entity
        .column("terms_url")
        .r#type(ColumnType::Text)
        .nullable(true);
    trust_entity
        .column("privacy_url")
        .r#type(ColumnType::Text)
        .nullable(true);
    trust_entity
        .column("role")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    trust_entity
        .column("state")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    trust_entity
        .column("trust_anchor_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key("FK-TrustEntity-TrustAnchorId", "trust_anchor", "id");
    trust_entity
        .column("organisation_id")
        .r#type(ColumnType::Uuid)
        .nullable(true)
        .foreign_key("FK-TrustEntity-OrganisationId", "organisation", "id");
    trust_entity
        .column("type")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    trust_entity
        .column("entity_key")
        .r#type(ColumnType::String(Some(4000)))
        .nullable(false)
        .default(None);
    trust_entity
        .column("content")
        .r#type(ColumnType::Blob)
        .nullable(true);
    trust_entity
        .column("deactivated_at")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(true);
}

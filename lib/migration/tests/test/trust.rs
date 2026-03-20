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

#[tokio::test]
async fn test_db_schema_trust_list_publication() {
    let schema = get_schema().await;

    let trust_list_publication = schema.table("trust_list_publication").columns(&[
        "id",
        "created_date",
        "last_modified",
        "name",
        "role",
        "type",
        "metadata",
        "deactivated_at",
        "content",
        "sequence_number",
        "organisation_id",
        "identifier_id",
        "key_id",
        "certificate_id",
    ]);
    trust_list_publication
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    trust_list_publication
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    trust_list_publication
        .column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    trust_list_publication
        .column("name")
        .r#type(ColumnType::Text)
        .nullable(false)
        .default(None);
    trust_list_publication
        .column("role")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    trust_list_publication
        .column("type")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    trust_list_publication
        .column("metadata")
        .r#type(ColumnType::Blob)
        .nullable(false)
        .default(None);
    trust_list_publication
        .column("deactivated_at")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(true);
    trust_list_publication
        .column("content")
        .r#type(ColumnType::Blob)
        .nullable(false)
        .default(None);
    trust_list_publication
        .column("sequence_number")
        .r#type(ColumnType::Unsigned)
        .nullable(false)
        .default(None);
    trust_list_publication
        .column("organisation_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key(
            "fk-TrustListPublication-OrganisationId",
            "organisation",
            "id",
        );
    trust_list_publication
        .column("identifier_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key("fk-TrustListPublication-IdentifierId", "identifier", "id");
    trust_list_publication
        .column("key_id")
        .r#type(ColumnType::Uuid)
        .nullable(true)
        .foreign_key("fk-TrustListPublication-KeyId", "key", "id");
    trust_list_publication
        .column("certificate_id")
        .r#type(ColumnType::Uuid)
        .nullable(true)
        .foreign_key("fk-TrustListPublication-CertificateId", "certificate", "id");
}

#[tokio::test]
async fn test_db_schema_trust_entry() {
    let schema = get_schema().await;

    let trust_entry = schema.table("trust_entry").columns(&[
        "id",
        "created_date",
        "last_modified",
        "status",
        "metadata",
        "trust_list_publication_id",
        "identifier_id",
    ]);
    trust_entry
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    trust_entry
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    trust_entry
        .column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    trust_entry
        .column("status")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    trust_entry
        .column("metadata")
        .r#type(ColumnType::Blob)
        .nullable(false)
        .default(None);
    trust_entry
        .column("trust_list_publication_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key(
            "fk-TrustEntry-TrustListPublicationId",
            "trust_list_publication",
            "id",
        );
    trust_entry
        .column("identifier_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key("fk-TrustEntry-IdentifierId", "identifier", "id");
}

#[tokio::test]
async fn test_db_schema_trust_collection() {
    let schema = get_schema().await;

    let mut columns = vec![
        "id",
        "created_date",
        "last_modified",
        "deactivated_at",
        "name",
        "organisation_id",
        "remote_trust_collection_url",
    ];
    if schema.backend() == DbBackend::MySql {
        columns.push("deactivated_at_materialized");
    }
    let trust_entry = schema.table("trust_collection").columns(&columns).index(
        "index-TrustCollection-Name-DeactivatedAt-Unique",
        true,
        &["name", "deactivated_at_materialized"],
    );
    trust_entry
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    trust_entry
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    trust_entry
        .column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    trust_entry
        .column("deactivated_at")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(true);
    trust_entry
        .column("name")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    trust_entry
        .column("remote_trust_collection_url")
        .r#type(ColumnType::Text)
        .nullable(true);
    trust_entry
        .column("organisation_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key("fk-TrustCollection-OrganisationId", "organisation", "id");
}

#[tokio::test]
async fn test_db_schema_trust_subscription() {
    let schema = get_schema().await;

    let mut columns = vec![
        "id",
        "created_date",
        "last_modified",
        "deactivated_at",
        "name",
        "reference",
        "type",
        "state",
        "role",
        "trust_collection_id",
    ];
    if schema.backend() == DbBackend::MySql {
        columns.push("deactivated_at_materialized");
    }
    let trust_entry = schema
        .table("trust_list_subscription")
        .columns(&columns)
        .index(
            "index-TrustListSubscription-Name-DeactivatedAt-Unique",
            true,
            &["name", "deactivated_at_materialized"],
        )
        .index(
            "index-TrustListSubscription-Reference-DeactivatedAt-Unique",
            true,
            &["reference", "deactivated_at_materialized"],
        );
    trust_entry
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    trust_entry
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    trust_entry
        .column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    trust_entry
        .column("deactivated_at")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(true);
    trust_entry
        .column("name")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    trust_entry
        .column("reference")
        .r#type(ColumnType::Text)
        .nullable(false)
        .default(None);
    trust_entry
        .column("role")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    trust_entry
        .column("state")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    trust_entry
        .column("trust_collection_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key(
            "fk-TrustListSubscription-TrustCollectionId",
            "trust_collection",
            "id",
        );
}

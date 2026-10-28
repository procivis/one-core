use sea_orm::DbBackend;

use crate::fixtures::{ColumnType, get_schema};

#[tokio::test]
async fn test_db_schema_trust_list_publication() {
    let schema = get_schema().await;

    let mut columns = vec![
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
    ];
    if schema.backend() == DbBackend::MySql {
        columns.extend(["deactivated_at_materialized"]);
    }

    let mut index_columns1 = vec!["name", "organisation_id"];
    if schema.backend() == DbBackend::MySql {
        index_columns1.push("deactivated_at_materialized")
    } else {
        index_columns1.push("deactivated_at")
    }

    let trust_list_publication = schema
        .table("trust_list_publication")
        .columns(&columns)
        .index(
            "index-TrustPublication-Name-Org-DeactivatedAt-Unique",
            true,
            &index_columns1,
        );
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
        .r#type(ColumnType::String(None))
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
        .r#type(ColumnType::Integer)
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

    let trust_entry = schema
        .table("trust_entry")
        .columns(&[
            "id",
            "created_date",
            "last_modified",
            "state",
            "metadata",
            "trust_list_publication_id",
            "identifier_id",
        ])
        .index(
            "index-TrustEntry-IdentifierId-Publication-Unique",
            true,
            &["identifier_id", "trust_list_publication_id"],
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
        .column("state")
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
        "ecosystem",
    ];
    if schema.backend() == DbBackend::MySql {
        columns.push("deactivated_at_materialized");
    }
    let mut index_columns1 = vec!["name", "organisation_id"];
    if schema.backend() == DbBackend::MySql {
        index_columns1.push("deactivated_at_materialized")
    } else {
        index_columns1.push("deactivated_at")
    }

    let trust_entry = schema.table("trust_collection").columns(&columns).index(
        "index-TrustCol-Name-Org-DeactivatedAt-Unique",
        true,
        &index_columns1,
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
    trust_entry
        .column("ecosystem")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
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
    columns.push("reference_hash");

    let mut index_columns1 = vec!["name", "trust_collection_id"];
    if schema.backend() == DbBackend::MySql {
        index_columns1.push("deactivated_at_materialized")
    } else {
        index_columns1.push("deactivated_at")
    }

    let mut index_columns2 = vec!["reference_hash", "trust_collection_id"];
    if schema.backend() == DbBackend::MySql {
        index_columns2.push("deactivated_at_materialized")
    } else {
        index_columns2.push("deactivated_at")
    }

    let trust_entry = schema
        .table("trust_list_subscription")
        .columns(&columns)
        .index(
            "index-TrustListSubscription-Name-Col-DeactivatedAt-Unique",
            true,
            &index_columns1,
        )
        .index(
            "index-TrustListSubscription-Reference-Col-DeactivatedAt-Unique",
            true,
            &index_columns2,
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
        .column("reference_hash")
        .r#type(ColumnType::String(Some(64)))
        .nullable(false)
        .default(None);
    trust_entry
        .column("role")
        .r#type(ColumnType::String(None))
        .nullable(true)
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

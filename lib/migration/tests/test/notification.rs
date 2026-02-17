use crate::fixtures::{ColumnType, get_schema};

#[tokio::test]
async fn test_db_schema_notification() {
    let schema = get_schema().await;

    let notification = schema
        .table("notification")
        .columns(&[
            "id",
            "url",
            "payload",
            "created_date",
            "next_try_date",
            "tries_count",
            "type",
            "history_target",
            "organisation_id",
        ])
        .index("index-Notification-CreatedDate", false, &["created_date"])
        .index(
            "index-Notification-Type_NextTryDate",
            false,
            &["type", "next_try_date"],
        );
    notification
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    notification
        .column("url")
        .r#type(ColumnType::Text)
        .nullable(false)
        .default(None);
    notification
        .column("payload")
        .r#type(ColumnType::Blob)
        .nullable(false)
        .default(None);
    notification
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    notification
        .column("next_try_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    notification
        .column("tries_count")
        .r#type(ColumnType::Unsigned)
        .nullable(false)
        .default(None);
    notification
        .column("type")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    notification
        .column("history_target")
        .r#type(ColumnType::String(None))
        .nullable(true);
    notification
        .column("organisation_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key("fk-Notification-OrganisationId", "organisation", "id");
}

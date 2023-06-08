use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter, Set,
};
use time::OffsetDateTime;

use crate::entities::{credential_schema, CredentialSchema};

pub(crate) async fn delete_credential_schema(
    db: &DatabaseConnection,
    id: &str,
) -> Result<(), DbErr> {
    let result: Vec<credential_schema::Model> = CredentialSchema::find_by_id(id)
        .filter(credential_schema::Column::DeletedAt.is_null())
        .all(db)
        .await?;

    if result.is_empty() {
        return Err(DbErr::RecordNotFound(format!(
            "CredentialSchema id: '{id}' not found"
        )));
    }

    let now = OffsetDateTime::now_utc();

    let mut database_errors: Vec<DbErr> = vec![];
    for credential_schema in result {
        if let Some(error) =
            delete_credential_schema_from_database(db, credential_schema, now).await
        {
            database_errors.push(error);
        }
    }

    if !database_errors.is_empty() {
        return Err(DbErr::Custom(format!(
            "{} database errors occurred.\nDetails:\n{:?}",
            database_errors.len(),
            database_errors
        )));
    }

    Ok(())
}

async fn delete_credential_schema_from_database(
    db: &DatabaseConnection,
    credential_schema: credential_schema::Model,
    now: OffsetDateTime,
) -> Option<DbErr> {
    let mut value: credential_schema::ActiveModel = credential_schema.into();
    value.deleted_at = Set(Some(now));
    value.reset(credential_schema::Column::DeletedAt);

    value.update(db).await.err()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utilities::*;

    #[tokio::test]
    async fn delete_credential_schema_test_simple_without_claims() {
        let database = setup_test_database_and_connection().await.unwrap();

        let credential_schema_id = insert_credential_schema_to_database(&database, None)
            .await
            .unwrap();

        let result = delete_credential_schema(&database, &credential_schema_id).await;
        assert!(result.is_ok());

        let deleted_schema = get_credential_schema_with_id(&database, &credential_schema_id)
            .await
            .unwrap();
        assert!(deleted_schema.is_some());

        let now = OffsetDateTime::now_utc();
        let deleted_at = deleted_schema.unwrap().deleted_at;
        assert!(deleted_at.is_some());
        assert!(are_datetimes_within_minute(now, deleted_at.unwrap()));
    }

    #[tokio::test]
    async fn delete_credential_schema_test_schema_cannot_be_deleted_twice() {
        let database = setup_test_database_and_connection().await.unwrap();

        let predefined_deletion_date = Some(get_dummy_date());

        let credential_schema_id =
            insert_credential_schema_to_database(&database, predefined_deletion_date)
                .await
                .unwrap();

        let result = delete_credential_schema(&database, &credential_schema_id).await;
        assert!(result.is_err_and(|error| matches!(error, DbErr::RecordNotFound(_))));

        let deleted_schema = get_credential_schema_with_id(&database, &credential_schema_id)
            .await
            .unwrap();
        assert!(deleted_schema.is_some());
        assert_eq!(predefined_deletion_date, deleted_schema.unwrap().deleted_at);
    }
}

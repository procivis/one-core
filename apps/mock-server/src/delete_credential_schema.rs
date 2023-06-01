use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter, Set,
};

use one_core::entities::{claim_schema, credential_schema, ClaimSchema, CredentialSchema};

pub(crate) async fn delete_credential_schema(
    db: &DatabaseConnection,
    id: u32,
) -> Result<(), DbErr> {
    let result: Vec<(credential_schema::Model, Vec<claim_schema::Model>)> =
        CredentialSchema::find_by_id(id)
            .find_with_related(ClaimSchema)
            .filter(credential_schema::Column::DeletedAt.is_null())
            .filter(claim_schema::Column::DeletedAt.is_null())
            .all(db)
            .await?;

    if result.is_empty() {
        return Err(DbErr::RecordNotFound(format!(
            "CredentialSchema id: '{id}' not found"
        )));
    }

    let now = Utc::now();

    let mut database_errors: Vec<DbErr> = vec![];
    for (credential_schema, claim_schemas) in result {
        if let Some(error) =
            delete_credential_schema_from_database(db, credential_schema, now).await
        {
            database_errors.push(error);
        }

        database_errors.append(
            &mut delete_claim_schemas(db, claim_schemas, now)
                .await
                .err()
                .unwrap_or(vec![]),
        );
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
    now: DateTime<Utc>,
) -> Option<DbErr> {
    let mut value: credential_schema::ActiveModel = credential_schema.into();
    value.deletedAt = Set(Some(now));
    value.reset(credential_schema::Column::DeletedAt);

    value.update(db).await.err()
}

async fn delete_claim_schemas(
    db: &DatabaseConnection,
    claim_schemas: Vec<claim_schema::Model>,
    now: DateTime<Utc>,
) -> Result<(), Vec<DbErr>> {
    let mut database_errors: Vec<DbErr> = vec![];

    for claim_schema in claim_schemas {
        let result = delete_claim_schema(db, claim_schema, now).await;
        if let Err(error) = result {
            database_errors.push(error);
        }
    }

    match database_errors.len() {
        0 => Ok(()),
        _ => Err(database_errors),
    }
}

async fn delete_claim_schema(
    db: &DatabaseConnection,
    claim_schema: claim_schema::Model,
    now: DateTime<Utc>,
) -> Result<claim_schema::Model, DbErr> {
    let mut claim_schema: claim_schema::ActiveModel = claim_schema.into();
    claim_schema.deletedAt = Set(Some(now));
    claim_schema.reset(claim_schema::Column::DeletedAt);

    claim_schema.update(db).await
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

        let result = delete_credential_schema(&database, credential_schema_id).await;
        assert!(result.is_ok());

        let deleted_schema = get_credential_schema_with_id(&database, credential_schema_id)
            .await
            .unwrap();
        assert!(deleted_schema.is_some());

        let now = Utc::now();
        let deleted_at = deleted_schema.unwrap().deletedAt;
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

        let result = delete_credential_schema(&database, credential_schema_id).await;
        assert!(result.is_err_and(|error| matches!(error, DbErr::RecordNotFound(_))));

        let deleted_schema = get_credential_schema_with_id(&database, credential_schema_id)
            .await
            .unwrap();
        assert!(deleted_schema.is_some());
        assert_eq!(predefined_deletion_date, deleted_schema.unwrap().deletedAt);
    }

    #[tokio::test]
    async fn delete_credential_schema_test_with_claims() {
        let database = setup_test_database_and_connection().await.unwrap();

        let credential_schema_id = insert_credential_schema_to_database(&database, None)
            .await
            .unwrap();

        let claim_one = insert_claim_schema_to_database(&database, credential_schema_id, None)
            .await
            .unwrap();
        let claim_two = insert_claim_schema_to_database(&database, credential_schema_id, None)
            .await
            .unwrap();

        let predefined_deletion_date = Some(get_dummy_date());
        let claim_three = insert_claim_schema_to_database(
            &database,
            credential_schema_id,
            predefined_deletion_date,
        )
        .await
        .unwrap();

        let result = delete_credential_schema(&database, credential_schema_id).await;
        assert!(result.is_ok());

        let now = Utc::now();
        let deleted_schema = get_credential_schema_with_id(&database, credential_schema_id)
            .await
            .unwrap();
        assert!(deleted_schema.is_some());
        assert!(are_datetimes_within_minute(
            now,
            deleted_schema.unwrap().deletedAt.unwrap()
        ));

        let deleted_claim_one = get_claim_schema_with_id(&database, claim_one)
            .await
            .unwrap();
        assert!(deleted_claim_one.is_some());
        assert!(are_datetimes_within_minute(
            now,
            deleted_claim_one.unwrap().deletedAt.unwrap()
        ));

        let deleted_claim_two = get_claim_schema_with_id(&database, claim_two)
            .await
            .unwrap();
        assert!(deleted_claim_two.is_some());
        assert!(are_datetimes_within_minute(
            now,
            deleted_claim_two.unwrap().deletedAt.unwrap()
        ));

        let deleted_claim_three = get_claim_schema_with_id(&database, claim_three)
            .await
            .unwrap();
        assert!(deleted_claim_three.is_some());
        assert_eq!(
            predefined_deletion_date,
            deleted_claim_three.unwrap().deletedAt
        );
    }
}

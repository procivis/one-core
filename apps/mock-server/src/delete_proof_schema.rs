use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter, Set,
};
use time::OffsetDateTime;

use one_core::entities::{proof_schema, ProofSchema};

pub(crate) async fn delete_proof_schema(db: &DatabaseConnection, id: u32) -> Result<(), DbErr> {
    let result = ProofSchema::find_by_id(id)
        .filter(proof_schema::Column::DeletedAt.is_null())
        .one(db)
        .await?;

    let schema = result.ok_or(DbErr::RecordNotFound(format!(
        "ProofSchema id: '{id}' not found"
    )))?;

    let now = OffsetDateTime::now_utc();
    mark_proof_schema_as_deleted(db, schema, now).await
}

async fn mark_proof_schema_as_deleted(
    db: &DatabaseConnection,
    proof_schema: proof_schema::Model,
    deleted_at: OffsetDateTime,
) -> Result<(), DbErr> {
    let mut value: proof_schema::ActiveModel = proof_schema.into();
    value.deleted_at = Set(Some(deleted_at));
    value.reset(proof_schema::Column::DeletedAt);
    value.update(db).await?;
    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::test_utilities::*;

    #[tokio::test]
    async fn delete_proof_schema_test() {
        let database = setup_test_database_and_connection().await.unwrap();

        let schema_id = insert_proof_schema_to_database(&database, None)
            .await
            .unwrap();

        let result = delete_proof_schema(&database, schema_id).await;
        assert!(result.is_ok());

        let deleted_schema = get_proof_schema_with_id(&database, schema_id)
            .await
            .unwrap();
        assert!(deleted_schema.is_some());

        let now = OffsetDateTime::now_utc();
        let deleted_at = deleted_schema.unwrap().deleted_at;
        assert!(deleted_at.is_some());
        assert!(are_datetimes_within_minute(now, deleted_at.unwrap()));
    }

    #[tokio::test]
    async fn delete_proof_schema_test_schema_cannot_be_deleted_twice() {
        let database = setup_test_database_and_connection().await.unwrap();

        let predefined_deletion_date = Some(get_dummy_date());

        let schema_id = insert_proof_schema_to_database(&database, predefined_deletion_date)
            .await
            .unwrap();

        let result = delete_proof_schema(&database, schema_id).await;
        assert!(result.is_err_and(|error| matches!(error, DbErr::RecordNotFound(_))));

        let deleted_schema = get_proof_schema_with_id(&database, schema_id)
            .await
            .unwrap();
        assert!(deleted_schema.is_some());
        assert_eq!(predefined_deletion_date, deleted_schema.unwrap().deleted_at);
    }
}

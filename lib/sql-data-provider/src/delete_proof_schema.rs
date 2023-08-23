use one_core::repository::error::DataLayerError;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter, Set,
};
use time::OffsetDateTime;

use crate::OldProvider;

use crate::entity::{proof_schema, ProofSchema};

impl OldProvider {
    pub async fn delete_proof_schema(&self, id: &str) -> Result<(), DataLayerError> {
        let result = ProofSchema::find_by_id(id)
            .filter(proof_schema::Column::DeletedAt.is_null())
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        let schema = result.ok_or(DataLayerError::RecordNotFound)?;

        let now = OffsetDateTime::now_utc();
        mark_proof_schema_as_deleted(&self.db, schema, now)
            .await
            .map_err(|_| DataLayerError::RecordNotUpdated)
    }
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

    use crate::test_utilities::*;

    use super::*;

    #[tokio::test]
    async fn delete_proof_schema_test() {
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let schema_id =
            insert_proof_schema_to_database(&data_layer.db, None, &organisation_id, "Proof1")
                .await
                .unwrap();

        let result = data_layer.delete_proof_schema(&schema_id).await;
        assert!(result.is_ok());

        let deleted_schema = get_proof_schema_with_id(&data_layer.db, &schema_id)
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
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();

        let predefined_deletion_date = Some(get_dummy_date());

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let schema_id = insert_proof_schema_to_database(
            &data_layer.db,
            predefined_deletion_date,
            &organisation_id,
            "Proof1",
        )
        .await
        .unwrap();

        let result = data_layer.delete_proof_schema(&schema_id).await;
        assert!(result.is_err_and(|error| matches!(error, DataLayerError::RecordNotFound)));

        let deleted_schema = get_proof_schema_with_id(&data_layer.db, &schema_id)
            .await
            .unwrap();
        assert!(deleted_schema.is_some());
        assert_eq!(predefined_deletion_date, deleted_schema.unwrap().deleted_at);
    }
}

use one_core::repository::error::DataLayerError;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter, Set,
};
use time::OffsetDateTime;

use crate::OldProvider;

use crate::entity::{credential_schema, CredentialSchema};

impl OldProvider {
    pub async fn delete_credential_schema(&self, id: &str) -> Result<(), DataLayerError> {
        let result: Vec<credential_schema::Model> = CredentialSchema::find_by_id(id)
            .filter(credential_schema::Column::DeletedAt.is_null())
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        if result.is_empty() {
            return Err(DataLayerError::RecordNotFound);
        }

        let now = OffsetDateTime::now_utc();

        let mut database_errors: Vec<DbErr> = vec![];
        for credential_schema in result {
            if let Some(error) =
                delete_credential_schema_from_database(&self.db, credential_schema, now).await
            {
                database_errors.push(error);
            }
        }

        if !database_errors.is_empty() {
            return Err(DataLayerError::GeneralRuntimeError(format!(
                "{} database errors occurred.\nDetails:\n{:?}",
                database_errors.len(),
                database_errors
            )));
        }

        Ok(())
    }
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

    use crate::test_utilities::*;

    use super::*;

    #[tokio::test]
    async fn delete_credential_schema_test_simple_without_claims() {
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let credential_schema_id = insert_credential_schema_to_database(
            &data_layer.db,
            None,
            &organisation_id,
            "Credential1",
        )
        .await
        .unwrap();

        let result = data_layer
            .delete_credential_schema(&credential_schema_id)
            .await;
        assert!(result.is_ok());

        let deleted_schema = get_credential_schema_by_id(&data_layer.db, &credential_schema_id)
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
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();

        let predefined_deletion_date = Some(get_dummy_date());

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let credential_schema_id = insert_credential_schema_to_database(
            &data_layer.db,
            predefined_deletion_date,
            &organisation_id,
            "Credential1",
        )
        .await
        .unwrap();

        let result = data_layer
            .delete_credential_schema(&credential_schema_id)
            .await;
        assert!(result.is_err_and(|error| matches!(error, DataLayerError::RecordNotFound)));

        let deleted_schema = get_credential_schema_by_id(&data_layer.db, &credential_schema_id)
            .await
            .unwrap();
        assert!(deleted_schema.is_some());
        assert_eq!(predefined_deletion_date, deleted_schema.unwrap().deleted_at);
    }
}

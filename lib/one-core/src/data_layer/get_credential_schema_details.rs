use sea_orm::{EntityTrait, ModelTrait};

use crate::data_layer::data_model::CredentialSchemaResponse;
use crate::data_layer::entities::{claim_schema, credential_schema, ClaimSchema, CredentialSchema};
use crate::data_layer::{DataLayer, DataLayerError};

impl DataLayer {
    pub async fn get_credential_schema_details(
        &self,
        uuid: &str,
    ) -> Result<CredentialSchemaResponse, DataLayerError> {
        let schema: credential_schema::Model = CredentialSchema::find_by_id(uuid)
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?
            .ok_or(DataLayerError::RecordNotFound)?;

        let claims: Vec<claim_schema::Model> = schema
            .find_related(ClaimSchema)
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        Ok(CredentialSchemaResponse::from_model(schema, claims))
    }
}

#[cfg(test)]
mod tests {

    use crate::data_layer::{test_utilities::*, DataLayerError};

    use uuid::Uuid;

    #[tokio::test]
    async fn test_get_credential_schemas_simple() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        const NON_EXISTING_UUID: &str = "ba439149-f313-4568-8dcb-8106bb518618";

        let result = data_layer
            .get_credential_schema_details(NON_EXISTING_UUID)
            .await;
        assert!(result.is_err_and(|error| matches!(error, DataLayerError::RecordNotFound)));

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let uuid = insert_credential_schema_to_database(&data_layer.db, None, &organisation_id)
            .await
            .unwrap();

        let result = data_layer.get_credential_schema_details(&uuid).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(uuid, response.id);
    }

    #[tokio::test]
    async fn test_get_credential_schemas_multiple_claims() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let uuid = insert_credential_schema_to_database(&data_layer.db, None, &organisation_id)
            .await
            .unwrap();

        insert_many_claims_schema_to_database(
            &data_layer.db,
            &uuid,
            &vec![Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()],
        )
        .await
        .unwrap();

        let result = data_layer.get_credential_schema_details(&uuid).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(uuid, response.id);
        assert_eq!(3, response.claims.len());
    }
}

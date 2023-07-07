use sea_orm::EntityTrait;

use crate::data_layer::data_model::CredentialSchemaResponse;
use crate::data_layer::entities::{credential_schema, CredentialSchema};
use crate::data_layer::{DataLayer, DataLayerError};

use super::common_queries;

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

        let claims = common_queries::fetch_credential_schema_claim_schemas(
            &self.db,
            vec![schema.id.clone()].as_slice(),
        )
        .await?;

        Ok(CredentialSchemaResponse::from_model(schema, &claims))
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

        let uuid = insert_credential_schema_to_database(
            &data_layer.db,
            None,
            &organisation_id,
            "Credential1",
        )
        .await
        .unwrap();

        let result = data_layer.get_credential_schema_details(&uuid).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(uuid, response.id);
    }

    #[tokio::test]
    async fn test_get_credential_schemas_multiple_claims_with_order() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let claims_count: usize = 50;

        let mut new_claims: Vec<(Uuid, bool, u32)> = (0..claims_count)
            .map(|i| (Uuid::new_v4(), i % 2 == 0, i as u32))
            .collect();

        // Seems that sqlite keeps the order of insertion. We sort by UUID to mimic
        // MariaDB behaviour and reproduce unordered response
        new_claims.sort_by(|a, b| a.0.cmp(&b.0));

        let uuid = insert_credential_schema_to_database(
            &data_layer.db,
            None,
            &organisation_id,
            "Credential1",
        )
        .await
        .unwrap();

        insert_many_claims_schema_to_database(&data_layer.db, &uuid, &new_claims)
            .await
            .unwrap();

        let result = data_layer.get_credential_schema_details(&uuid).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(uuid, response.id);
        assert_eq!(response.claims.len(), claims_count);

        // Now lets get back to the expected order and compare with the result
        new_claims.sort_by(|a, b| a.2.cmp(&b.2));

        assert!(new_claims
            .iter()
            .zip(response.claims.iter())
            .all(|(expected, result)| expected.0.to_string() == result.id));
    }
}

use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Select};

use crate::data_layer::data_model::ProofSchemaResponse;
use crate::data_layer::entities::{proof_schema, ProofSchema};
use crate::data_layer::{DataLayer, DataLayerError};

use super::common_queries;

impl DataLayer {
    pub async fn get_proof_schema_details(
        &self,
        uuid: &str,
    ) -> Result<ProofSchemaResponse, DataLayerError> {
        let proof_schema: proof_schema::Model = get_base_query(uuid)
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?
            .ok_or(DataLayerError::RecordNotFound)?;

        let claims =
            common_queries::fetch_proof_schema_claim_schemas(&self.db, &[proof_schema.id.clone()])
                .await?;

        Ok(ProofSchemaResponse::from_model(proof_schema, claims))
    }
}

fn get_base_query(uuid: &str) -> Select<ProofSchema> {
    ProofSchema::find_by_id(uuid).filter(proof_schema::Column::DeletedAt.is_null())
}

#[cfg(test)]
mod tests {
    use crate::data_layer::{entities::claim_schema::Datatype, test_utilities::*, DataLayerError};
    use uuid::Uuid;

    #[tokio::test]
    async fn test_get_proof_schemas_simple() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let result = data_layer
            .get_proof_schema_details(&Uuid::new_v4().to_string())
            .await;
        assert!(result.is_err_and(|error| matches!(error, DataLayerError::RecordNotFound)));

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let uuid =
            insert_proof_schema_to_database(&data_layer.db, None, &organisation_id, "Proof1")
                .await
                .unwrap();

        let result = data_layer.get_proof_schema_details(&uuid).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(uuid, response.id);
    }

    #[tokio::test]
    async fn test_get_proof_schemas_with_claims_and_credential_schemas() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let mut new_claims: Vec<(Uuid, bool, u32, Datatype)> = (0..50)
            .map(|i| (Uuid::new_v4(), i % 2 == 0, i, Datatype::String))
            .collect();

        // Seems that sqlite keeps the order of insertion. We sort by UUID to mimic
        // MariaDB behaviour and reproduce unordered response
        new_claims.sort_by(|a, b| a.0.cmp(&b.0));

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

        insert_many_claims_schema_to_database(&data_layer.db, &credential_schema_id, &new_claims)
            .await
            .unwrap();

        let proof_schema_id = insert_proof_schema_with_claims_to_database(
            &data_layer.db,
            None,
            &new_claims,
            &organisation_id,
        )
        .await
        .unwrap();

        let result = data_layer.get_proof_schema_details(&proof_schema_id).await;
        assert!(result.is_ok());

        // Now lets get back to the expected order and compare with the result
        new_claims.sort_by(|a, b| a.2.cmp(&b.2));

        let response = result.unwrap();
        assert_eq!(proof_schema_id, response.id);
        assert_eq!(response.claim_schemas.len(), 50);

        assert!(new_claims
            .iter()
            .zip(response.claim_schemas.iter())
            .all(|(expected, result)| expected.0.to_string() == result.id
                && expected.1 == result.is_required
                && result.credential_schema.id == credential_schema_id));
    }
}

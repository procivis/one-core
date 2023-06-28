use sea_orm::{ActiveModelTrait, Set};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::data_layer::{
    data_model::{CreateProofSchemaRequest, CreateProofSchemaResponse},
    entities::{proof_schema, proof_schema_claim},
    DataLayer, DataLayerError,
};

impl DataLayer {
    pub async fn create_proof_schema(
        &self,
        request: CreateProofSchemaRequest,
    ) -> Result<CreateProofSchemaResponse, DataLayerError> {
        let now = OffsetDateTime::now_utc();

        let proof_schema = proof_schema::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            name: Set(request.name),
            deleted_at: Set(None),
            created_date: Set(now),
            last_modified: Set(now),
            organisation_id: Set(request.organisation_id.to_string()),
            expire_duration: Set(request.expire_duration),
        }
        .insert(&self.db)
        .await
        .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        for claim_schema in request.claim_schemas {
            proof_schema_claim::ActiveModel {
                claim_schema_id: Set(claim_schema.id.to_string()),
                proof_schema_id: Set(proof_schema.id.clone()),
                is_required: Set(false),
            }
            .insert(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;
        }

        Ok(CreateProofSchemaResponse {
            id: proof_schema.id,
        })
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::EntityTrait;
    use uuid::Uuid;

    use crate::data_layer::data_model::{ClaimProofSchemaRequest, CreateProofSchemaRequest};
    use crate::data_layer::entities::{ProofSchema, ProofSchemaClaim};
    use crate::data_layer::test_utilities::{
        insert_credential_schema_to_database, insert_many_claims_schema_to_database,
        insert_organisation_to_database, setup_test_data_layer_and_connection,
    };
    use crate::data_layer::DataLayerError;

    fn create_schema() -> CreateProofSchemaRequest {
        CreateProofSchemaRequest {
            name: String::from("ProofSchema1"),
            organisation_id: Uuid::new_v4(),
            expire_duration: 10,
            claim_schemas: vec![],
        }
    }

    #[tokio::test]
    async fn create_proof_schema_test_simple_without_claims() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let proof_schemas_count = ProofSchema::find().all(&data_layer.db).await.unwrap().len();
        assert_eq!(0, proof_schemas_count);

        let proof_schema_claim_count = ProofSchemaClaim::find()
            .all(&data_layer.db)
            .await
            .unwrap()
            .len();
        assert_eq!(0, proof_schema_claim_count);

        let mut request = create_schema();

        request.organisation_id = Uuid::new_v4();

        insert_organisation_to_database(&data_layer.db, Some(request.organisation_id))
            .await
            .unwrap();

        let response = data_layer.create_proof_schema(request).await;
        assert!(response.is_ok());
        assert!(Uuid::parse_str(&response.unwrap().id).is_ok());

        let proof_schemas_count = ProofSchema::find().all(&data_layer.db).await.unwrap().len();
        assert_eq!(1, proof_schemas_count);
    }

    #[tokio::test]
    async fn create_proof_schema_test_with_not_existing_claim() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let proof_schemas_count = ProofSchema::find().all(&data_layer.db).await.unwrap().len();
        assert_eq!(0, proof_schemas_count);

        let proof_schema_claim_count = ProofSchemaClaim::find()
            .all(&data_layer.db)
            .await
            .unwrap()
            .len();
        assert_eq!(0, proof_schema_claim_count);

        let mut request = create_schema();
        request.claim_schemas = vec![ClaimProofSchemaRequest { id: Uuid::new_v4() }];

        let response = data_layer.create_proof_schema(request.clone()).await;
        assert!(response.is_err());
        assert!(matches!(
            response,
            Err(DataLayerError::GeneralRuntimeError(_))
        ))
    }

    #[tokio::test]
    async fn create_proof_schema_test_with_claims() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let proof_schemas_count = ProofSchema::find().all(&data_layer.db).await.unwrap().len();
        assert_eq!(0, proof_schemas_count);

        let proof_schema_claim_count = ProofSchemaClaim::find()
            .all(&data_layer.db)
            .await
            .unwrap()
            .len();
        assert_eq!(0, proof_schema_claim_count);

        let claim_ids = vec![Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let credential_id =
            insert_credential_schema_to_database(&data_layer.db, None, &organisation_id)
                .await
                .unwrap();

        insert_many_claims_schema_to_database(&data_layer.db, &credential_id, &claim_ids)
            .await
            .unwrap();

        let mut request = create_schema();
        request.claim_schemas = vec![
            ClaimProofSchemaRequest { id: claim_ids[0] },
            ClaimProofSchemaRequest { id: claim_ids[1] },
            ClaimProofSchemaRequest { id: claim_ids[2] },
        ];

        insert_organisation_to_database(&data_layer.db, Some(request.organisation_id))
            .await
            .unwrap();

        let response = data_layer.create_proof_schema(request.clone()).await;
        assert!(response.is_ok());
        assert!(Uuid::parse_str(&response.as_ref().unwrap().id).is_ok());

        let proof_schema_claims = ProofSchemaClaim::find().all(&data_layer.db).await.unwrap();
        assert_eq!(3, proof_schema_claims.len());

        assert!(proof_schema_claims
            .into_iter()
            .enumerate()
            .all(|(i, item)| {
                item.claim_schema_id == request.claim_schemas[i].id.to_string()
                    && item.proof_schema_id == response.as_ref().unwrap().id
            }));
    }
}

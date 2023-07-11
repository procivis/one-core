use sea_orm::{ActiveModelTrait, EntityTrait, Set, SqlErr};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::data_layer::{
    data_model::{CreateProofSchemaRequest, CreateProofSchemaResponse},
    entities::{proof_schema, proof_schema_claim_schema},
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
        .map_err(|e| match e.sql_err() {
            Some(sql_error) if matches!(sql_error, SqlErr::UniqueConstraintViolation(_)) => {
                DataLayerError::AlreadyExists
            }
            Some(_) | None => {
                dbg!(&e);
                DataLayerError::GeneralRuntimeError(e.to_string())
            }
        })?;

        if !request.claim_schemas.is_empty() {
            let proof_schema_claim_schema_relations: Vec<proof_schema_claim_schema::ActiveModel> =
                request
                    .claim_schemas
                    .iter()
                    .enumerate()
                    .map(|(i, claim_schema)| proof_schema_claim_schema::ActiveModel {
                        claim_schema_id: Set(claim_schema.id.to_string()),
                        proof_schema_id: Set(proof_schema.id.clone()),
                        required: Set(false),
                        order: Set(i as u32),
                    })
                    .collect();

            proof_schema_claim_schema::Entity::insert_many(proof_schema_claim_schema_relations)
                .exec(&self.db)
                .await
                .map_err(|e| {
                    dbg!(&e);
                    DataLayerError::GeneralRuntimeError(e.to_string())
                })?;
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
    use crate::data_layer::entities::{
        claim_schema::Datatype, ProofSchema, ProofSchemaClaimSchema,
    };
    use crate::data_layer::test_utilities::{
        insert_credential_schema_to_database, insert_many_claims_schema_to_database,
        insert_organisation_to_database, setup_test_data_layer_and_connection,
    };
    use crate::data_layer::DataLayerError;

    fn create_schema(organisation_id: &Uuid, name: &str) -> CreateProofSchemaRequest {
        CreateProofSchemaRequest {
            name: name.to_owned(),
            organisation_id: organisation_id.to_owned(),
            expire_duration: 10,
            claim_schemas: vec![],
        }
    }

    #[tokio::test]
    async fn create_proof_schema_test_simple_without_claims() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let proof_schemas_count = ProofSchema::find().all(&data_layer.db).await.unwrap().len();
        assert_eq!(0, proof_schemas_count);

        let proof_schema_claim_count = ProofSchemaClaimSchema::find()
            .all(&data_layer.db)
            .await
            .unwrap()
            .len();
        assert_eq!(0, proof_schema_claim_count);

        let organisation_id = Uuid::new_v4();

        let request = create_schema(&organisation_id, "Proof1");

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
    async fn create_proof_schema_test_simple_without_claims_duplicated_names() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let organisation_id = Uuid::new_v4();
        let organisation2_id = Uuid::new_v4();

        insert_organisation_to_database(&data_layer.db, Some(organisation_id))
            .await
            .unwrap();

        insert_organisation_to_database(&data_layer.db, Some(organisation2_id))
            .await
            .unwrap();

        assert!(data_layer
            .create_proof_schema(create_schema(&organisation_id, "Proof1"))
            .await
            .is_ok());

        // The same name is not allowed
        assert!(matches!(
            data_layer
                .create_proof_schema(create_schema(&organisation_id, "Proof1"))
                .await,
            Err(DataLayerError::AlreadyExists)
        ));

        // Case sensitive
        assert!(data_layer
            .create_proof_schema(create_schema(&organisation_id, "proof1"))
            .await
            .is_ok());

        // Case sensitive
        assert!(data_layer
            .create_proof_schema(create_schema(&organisation2_id, "Proof1"))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn create_proof_schema_test_with_not_existing_claim() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let proof_schemas_count = ProofSchema::find().all(&data_layer.db).await.unwrap().len();
        assert_eq!(0, proof_schemas_count);

        let proof_schema_claim_count = ProofSchemaClaimSchema::find()
            .all(&data_layer.db)
            .await
            .unwrap()
            .len();
        assert_eq!(0, proof_schema_claim_count);

        let organisation_id = Uuid::new_v4();

        insert_organisation_to_database(&data_layer.db, Some(organisation_id))
            .await
            .unwrap();

        let mut request = create_schema(&organisation_id, "Proof1");
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

        let proof_schema_claim_count = ProofSchemaClaimSchema::find()
            .all(&data_layer.db)
            .await
            .unwrap()
            .len();
        assert_eq!(0, proof_schema_claim_count);

        let new_claims: Vec<(Uuid, bool, u32, Datatype)> = (0..50)
            .map(|i| (Uuid::new_v4(), i % 2 == 0, i, Datatype::String))
            .collect();

        let organisation_id = Uuid::new_v4();

        insert_organisation_to_database(&data_layer.db, Some(organisation_id))
            .await
            .unwrap();

        let credential_id = insert_credential_schema_to_database(
            &data_layer.db,
            None,
            &organisation_id.to_string(),
            "Credential1",
        )
        .await
        .unwrap();

        insert_many_claims_schema_to_database(&data_layer.db, &credential_id, &new_claims)
            .await
            .unwrap();

        let mut request = create_schema(&organisation_id, "Proof1");
        request.claim_schemas = new_claims
            .iter()
            .map(|claim| ClaimProofSchemaRequest { id: claim.0 })
            .collect();

        let response = data_layer.create_proof_schema(request.clone()).await;
        assert!(response.is_ok());
        assert!(Uuid::parse_str(&response.as_ref().unwrap().id).is_ok());

        let proof_schema_claims = ProofSchemaClaimSchema::find()
            .all(&data_layer.db)
            .await
            .unwrap();

        assert!(proof_schema_claims
            .into_iter()
            .enumerate()
            .all(|(i, item)| {
                item.claim_schema_id == request.claim_schemas[i].id.to_string()
                    && item.proof_schema_id == response.as_ref().unwrap().id
            }));
    }
}

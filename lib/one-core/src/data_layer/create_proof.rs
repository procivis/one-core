use sea_orm::{ActiveModelTrait, EntityTrait, Set, SqlErr};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::data_layer::{DataLayer, DataLayerError};

use super::{
    common_queries::insert_proof_state,
    data_model::{CreateProofRequest, CreateProofResponse},
    entities::{proof, proof_schema, proof_state::ProofRequestState},
};

impl DataLayer {
    pub async fn create_proof(
        &self,
        request: CreateProofRequest,
    ) -> Result<CreateProofResponse, DataLayerError> {
        let now = OffsetDateTime::now_utc();

        let proof_schema = proof_schema::Entity::find_by_id(&request.proof_schema_id.to_string())
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?
            .ok_or(DataLayerError::RecordNotFound)?;

        if proof_schema.deleted_at.is_some() {
            return Err(DataLayerError::IncorrectParameters);
        }

        let proof = proof::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            created_date: Set(now),
            last_modified: Set(now),
            issuance_date: Set(now),
            did_id: Set(request.verifier_did),
            receiver_did_id: Set(None),
            proof_schema_id: Set(request.proof_schema_id.to_string()),
        }
        .insert(&self.db)
        .await
        .map_err(|e| match e.sql_err() {
            Some(sql_error) if matches!(sql_error, SqlErr::UniqueConstraintViolation(_)) => {
                DataLayerError::AlreadyExists
            }
            Some(sql_error) if matches!(sql_error, SqlErr::ForeignKeyConstraintViolation(_)) => {
                DataLayerError::RecordNotFound
            }
            Some(_) | None => {
                dbg!(&e);
                DataLayerError::GeneralRuntimeError(e.to_string())
            }
        })?;

        insert_proof_state(&self.db, &proof.id, now, now, ProofRequestState::Pending).await?;

        Ok(CreateProofResponse { id: proof.id })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use sea_orm::EntityTrait;
    use time::OffsetDateTime;
    use uuid::Uuid;

    use crate::data_layer::common_queries::get_proof_state;
    use crate::data_layer::data_model::{CreateProofRequest, Transport};
    use crate::data_layer::entities::claim_schema::Datatype;
    use crate::data_layer::entities::proof;
    use crate::data_layer::entities::proof_state::ProofRequestState;
    use crate::data_layer::test_utilities::{
        get_dummy_date, insert_credential_schema_to_database, insert_did,
        insert_many_claims_schema_to_database, insert_organisation_to_database,
        insert_proof_schema_with_claims_to_database, setup_test_data_layer_and_connection,
    };
    use crate::data_layer::{DataLayer, DataLayerError};

    async fn prepare_env(
        data_layer: &DataLayer,
        proof_schema_deleted_at: Option<OffsetDateTime>,
    ) -> (String, String) {
        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let credential_id = insert_credential_schema_to_database(
            &data_layer.db,
            None,
            &organisation_id,
            "Credential1",
        )
        .await
        .unwrap();

        let new_claims: Vec<(Uuid, bool, u32, Datatype)> = (0..10)
            .map(|i| (Uuid::new_v4(), i % 2 == 0, i, Datatype::String))
            .collect();

        insert_many_claims_schema_to_database(&data_layer.db, &credential_id, &new_claims)
            .await
            .unwrap();

        let proof_schema_id = insert_proof_schema_with_claims_to_database(
            &data_layer.db,
            proof_schema_deleted_at,
            &new_claims,
            &organisation_id,
        )
        .await
        .unwrap();

        (organisation_id, proof_schema_id)
    }

    #[tokio::test]
    async fn create_proof() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let (organisation_id, proof_schema_id) = prepare_env(&data_layer, None).await;

        let verifier_did = insert_did(&data_layer.db, "DID_NAME", "DID:123:KEY", &organisation_id)
            .await
            .unwrap();

        let request = CreateProofRequest {
            proof_schema_id: Uuid::from_str(&proof_schema_id).unwrap(),
            transport: Transport::ProcivisTemporary,
            verifier_did: verifier_did.clone(),
        };

        let result = data_layer.create_proof(request).await;

        assert!(result.is_ok());

        let proof_id = result.unwrap().id.clone();

        let inserted_proof = proof::Entity::find_by_id(&proof_id)
            .one(&data_layer.db)
            .await
            .unwrap()
            .unwrap();

        let state = get_proof_state(&data_layer.db, &proof_id).await.unwrap();

        assert_eq!(inserted_proof.proof_schema_id, proof_schema_id);
        assert_eq!(inserted_proof.did_id, verifier_did);
        assert_eq!(inserted_proof.receiver_did_id, None);
        assert_eq!(state, ProofRequestState::Pending);
    }

    #[tokio::test]
    async fn create_proof_incorrect_did() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let (_organisation_id, proof_schema_id) = prepare_env(&data_layer, None).await;

        // ID is not inserted to DB
        let verifier_did = Uuid::new_v4().to_string();

        let request = CreateProofRequest {
            proof_schema_id: Uuid::from_str(&proof_schema_id).unwrap(),
            transport: Transport::ProcivisTemporary,
            verifier_did: verifier_did.clone(),
        };

        let result = data_layer.create_proof(request).await;

        assert!(matches!(result, Err(DataLayerError::RecordNotFound)));
    }

    #[tokio::test]
    async fn create_proof_incorrect_schema() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let (organisation_id, _proof_schema_id) = prepare_env(&data_layer, None).await;

        // Random schema id - not in database
        let proof_schema_id = Uuid::new_v4();

        let verifier_did = insert_did(&data_layer.db, "DID_NAME", "DID:123:KEY", &organisation_id)
            .await
            .unwrap();

        let request = CreateProofRequest {
            proof_schema_id,
            transport: Transport::ProcivisTemporary,
            verifier_did: verifier_did.clone(),
        };

        let result = data_layer.create_proof(request).await;

        assert!(matches!(result, Err(DataLayerError::RecordNotFound)));
    }

    #[tokio::test]
    async fn create_proof_for_deleted_schema() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let (organisation_id, proof_schema_id) =
            prepare_env(&data_layer, Some(get_dummy_date())).await;

        let verifier_did = insert_did(&data_layer.db, "DID_NAME", "DID:123:KEY", &organisation_id)
            .await
            .unwrap();

        let request = CreateProofRequest {
            proof_schema_id: Uuid::from_str(&proof_schema_id).unwrap(),
            transport: Transport::ProcivisTemporary,
            verifier_did: verifier_did.clone(),
        };

        let result = data_layer.create_proof(request).await;

        assert!(matches!(result, Err(DataLayerError::IncorrectParameters)));
    }
}

use super::{
    common_queries,
    data_model::{CreateProofClaimRequest, ProofRequestState},
    entities::{claim, proof, proof_claim},
};
use crate::data_layer::{DataLayer, DataLayerError};
use sea_orm::{ActiveModelTrait, DbErr, EntityTrait, Set, Unchanged};
use time::OffsetDateTime;
use uuid::Uuid;

impl DataLayer {
    pub async fn set_proof_receiver_did_id(
        &self,
        proof_request_id: &str,
        did_id: &str,
    ) -> Result<(), DataLayerError> {
        let now = OffsetDateTime::now_utc();

        let model = proof::ActiveModel {
            id: Unchanged(proof_request_id.to_owned()),
            receiver_did_id: Set(Some(did_id.to_owned())),
            last_modified: Set(now),
            ..Default::default()
        };

        model.update(&self.db).await.map_err(|e| match e {
            DbErr::RecordNotUpdated => DataLayerError::RecordNotUpdated,
            _ => DataLayerError::GeneralRuntimeError(e.to_string()),
        })?;

        Ok(())
    }

    pub async fn set_proof_claims(
        &self,
        proof_request_id: &str,
        claims: Vec<CreateProofClaimRequest>,
    ) -> Result<(), DataLayerError> {
        let now = OffsetDateTime::now_utc();

        let claim_models: Vec<claim::ActiveModel> = claims
            .into_iter()
            .map(|claim| claim::ActiveModel {
                id: Set(Uuid::new_v4().to_string()),
                claim_schema_id: Set(claim.claim_schema_id),
                value: Set(claim.value),
                created_date: Set(now),
                last_modified: Set(now),
            })
            .collect();

        let proof_claim_models: Vec<proof_claim::ActiveModel> = claim_models
            .iter()
            .map(|claim| proof_claim::ActiveModel {
                claim_id: claim.id.to_owned(),
                proof_id: Set(proof_request_id.to_string()),
            })
            .collect();

        claim::Entity::insert_many(claim_models)
            .exec(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        proof_claim::Entity::insert_many(proof_claim_models)
            .exec(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        Ok(())
    }

    pub async fn set_proof_state(
        &self,
        proof_request_id: &str,
        state: ProofRequestState,
    ) -> Result<(), DataLayerError> {
        let now = OffsetDateTime::now_utc();
        common_queries::insert_proof_state(&self.db, proof_request_id, now, now, state.into()).await
    }
}

#[cfg(test)]
mod tests {

    use crate::data_layer::test_utilities::*;

    #[tokio::test]
    async fn test_set_proof_receiver_did_id() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let verifier_did_id = insert_did(
            &data_layer.db,
            "DID_VERIFIER",
            "did:key:verifier",
            &organisation_id,
        )
        .await
        .unwrap();

        let proof_schema_id =
            insert_proof_schema_to_database(&data_layer.db, None, &organisation_id, "proof-schema")
                .await
                .unwrap();

        let proof_id = insert_proof_request_to_database(
            &data_layer.db,
            &verifier_did_id,
            None,
            &proof_schema_id,
        )
        .await
        .unwrap();

        let receiver_did_id = insert_did(
            &data_layer.db,
            "DID_RECEIVER",
            "did:key:receiver",
            &organisation_id,
        )
        .await
        .unwrap();

        let result = data_layer
            .set_proof_receiver_did_id(&proof_id, &receiver_did_id)
            .await;

        assert!(result.is_ok());
        let proof_model = get_proof_by_id(&data_layer.db, &proof_id)
            .await
            .unwrap()
            .expect("Proof doesn't exist");

        assert_eq!(
            proof_model.receiver_did_id,
            Some(receiver_did_id.to_owned())
        );
    }
}

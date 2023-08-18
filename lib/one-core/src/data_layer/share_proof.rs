use time::OffsetDateTime;

use crate::data_layer::{
    common_queries::get_proof_state,
    common_queries::insert_proof_state,
    data_model::{ProofShareResponse, Transport},
    entities::proof_state::ProofRequestState,
    DataLayer, DataLayerError,
};

impl DataLayer {
    pub async fn share_proof(&self, proof_id: &str) -> Result<ProofShareResponse, DataLayerError> {
        let proof_state = get_proof_state(&self.db, proof_id).await?;

        match proof_state {
            ProofRequestState::Created | ProofRequestState::Pending => {
                if proof_state == ProofRequestState::Created {
                    let now = OffsetDateTime::now_utc();

                    insert_proof_state(&self.db, proof_id, now, now, ProofRequestState::Pending)
                        .await?;
                }

                Ok(ProofShareResponse {
                    proof_id: proof_id.to_string(),
                    transport: Transport::ProcivisTemporary,
                })
            }
            _ => Err(DataLayerError::AlreadyExists),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::data_layer::common_queries::insert_proof_state;
    use crate::data_layer::data_model::ProofRequestState;
    use crate::data_layer::entities::proof_state;
    use crate::data_layer::{entities::ProofState, test_utilities::*, DataLayer};
    use sea_orm::EntityTrait;
    use std::ops::Add;
    use time::{Duration, OffsetDateTime};
    use uuid::Uuid;

    struct TestData {
        pub data_layer: DataLayer,
        pub proof_id: String,
    }

    impl TestData {
        async fn new() -> Self {
            let data_layer = setup_test_data_layer_and_connection().await.unwrap();

            let organisation_id = insert_organisation_to_database(&data_layer.db, None)
                .await
                .unwrap();
            let did_id = insert_did(&data_layer.db, "did name", "test123", &organisation_id)
                .await
                .unwrap();
            let credential_schema_id = insert_credential_schema_to_database(
                &data_layer.db,
                None,
                &organisation_id,
                "test123",
            )
            .await
            .unwrap();

            let proof_schema_id =
                insert_proof_schema_to_database(&data_layer.db, None, &organisation_id, "test123")
                    .await
                    .unwrap();

            let new_claims: Vec<(Uuid, bool, u32, &str)> = (0..4)
                .map(|i| (Uuid::new_v4(), i % 2 == 0, i, "STRING"))
                .collect();
            insert_many_claims_schema_to_database(
                &data_layer.db,
                &credential_schema_id,
                &new_claims,
            )
            .await
            .unwrap();

            let proof_id =
                insert_proof_request_to_database(&data_layer.db, &did_id, None, &proof_schema_id)
                    .await
                    .unwrap();

            insert_proof_state_to_database(
                &data_layer.db,
                &proof_id,
                proof_state::ProofRequestState::Created,
            )
            .await
            .unwrap();

            Self {
                data_layer,
                proof_id,
            }
        }
    }

    #[tokio::test]
    async fn create_proof_test_simple() {
        let test_data = TestData::new().await;

        let share_proof = test_data.data_layer.share_proof(&test_data.proof_id).await;
        assert!(share_proof.is_ok());

        let proof_state_count = ProofState::find()
            .all(&test_data.data_layer.db)
            .await
            .unwrap()
            .len();
        assert_eq!(2, proof_state_count);

        let proof = test_data
            .data_layer
            .get_proof_details(&test_data.proof_id)
            .await;
        assert!(proof.is_ok());
        assert_eq!(ProofRequestState::Pending, proof.unwrap().state);
    }

    #[tokio::test]
    async fn create_proof_test_share_states() {
        let test_data = TestData::new().await;

        let share_proof = test_data.data_layer.share_proof(&test_data.proof_id).await;
        assert!(share_proof.is_ok());

        let we_can_share_same_proof_many_times =
            test_data.data_layer.share_proof(&test_data.proof_id).await;
        assert!(we_can_share_same_proof_many_times.is_ok());

        let now = OffsetDateTime::now_utc();
        let later: OffsetDateTime = now.add(Duration::new(1, 0));
        insert_proof_state(
            &test_data.data_layer.db,
            &test_data.proof_id,
            later,
            now,
            proof_state::ProofRequestState::Error,
        )
        .await
        .unwrap();

        let but_we_cannot_share_it_when_its_state_is_not_correct =
            test_data.data_layer.share_proof(&test_data.proof_id).await;
        assert!(but_we_cannot_share_it_when_its_state_is_not_correct.is_err());

        let proof_state_count = ProofState::find()
            .all(&test_data.data_layer.db)
            .await
            .unwrap()
            .len();
        assert_eq!(3, proof_state_count);
    }
}

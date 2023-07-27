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
            ProofRequestState::Created
            | ProofRequestState::Offered
            | ProofRequestState::Pending => {
                let now = OffsetDateTime::now_utc();

                if proof_state == ProofRequestState::Created {
                    insert_proof_state(&self.db, proof_id, now, now, ProofRequestState::Offered)
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
    use crate::data_layer::entities::proof_state;
    use crate::data_layer::{
        entities::{claim_schema::Datatype, ProofState},
        test_utilities::*,
        DataLayer,
    };
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

            let new_claims: Vec<(Uuid, bool, u32, Datatype)> = (0..4)
                .map(|i| (Uuid::new_v4(), i % 2 == 0, i, Datatype::String))
                .collect();
            insert_many_claims_schema_to_database(
                &data_layer.db,
                &credential_schema_id,
                &new_claims,
            )
            .await
            .unwrap();

            let proof_id = insert_proof(&data_layer.db, &proof_schema_id, &did_id)
                .await
                .unwrap();

            let proof_state_count = ProofState::find().all(&data_layer.db).await.unwrap().len();
            assert_eq!(1, proof_state_count);

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
    }

    #[tokio::test]
    async fn create_proof_test_share_three_states() {
        let test_data = TestData::new().await;

        let share_proof = test_data.data_layer.share_proof(&test_data.proof_id).await;
        assert!(share_proof.is_ok());

        let we_can_share_same_proof_many_times =
            test_data.data_layer.share_proof(&test_data.proof_id).await;
        assert!(we_can_share_same_proof_many_times.is_ok());

        let now = OffsetDateTime::now_utc();
        insert_proof_state(
            &test_data.data_layer.db,
            &test_data.proof_id,
            now,
            now,
            proof_state::ProofRequestState::Pending,
        )
        .await
        .unwrap();

        let we_can_also_share_in_pending_state =
            &test_data.data_layer.share_proof(&test_data.proof_id).await;
        assert!(we_can_also_share_in_pending_state.is_ok());

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
        assert_eq!(4, proof_state_count);
    }
}

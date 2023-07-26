use crate::data_layer::{DataLayer, DataLayerError};
use time::OffsetDateTime;

use crate::data_layer::common_queries::{get_proof_state, insert_proof_state};
use crate::data_layer::entities::proof_state;

impl DataLayer {
    pub async fn reject_proof_request(&self, proof_request_id: &str) -> Result<(), DataLayerError> {
        let proof_request_state = get_proof_state(&self.db, proof_request_id).await?;

        match proof_request_state {
            proof_state::ProofRequestState::Offered => {
                let now = OffsetDateTime::now_utc();

                insert_proof_state(
                    &self.db,
                    proof_request_id,
                    now,
                    now,
                    proof_state::ProofRequestState::Rejected,
                )
                .await?;

                Ok(())
            }
            _ => Err(DataLayerError::RecordNotUpdated),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Add;
    use time::Duration;

    use crate::data_layer::{
        common_queries::{get_proof_state, insert_proof_state},
        entities::proof_state::ProofRequestState,
        test_utilities::*,
        DataLayer, DataLayerError,
    };

    struct TestData {
        pub data_layer: DataLayer,
        pub proof_request_id: String,
    }

    impl TestData {
        async fn new() -> Self {
            let data_layer = setup_test_data_layer_and_connection().await.unwrap();

            let organisation_id = insert_organisation_to_database(&data_layer.db, None)
                .await
                .unwrap();

            let did_id = insert_did(&data_layer.db, "did name", "did:did", &organisation_id)
                .await
                .unwrap();

            let proof_schema_id = insert_proof_schema_to_database(
                &data_layer.db,
                None,
                &organisation_id,
                "ProofSchema1",
            )
            .await
            .unwrap();

            let proof_request_id =
                insert_proof_request_to_database(&data_layer.db, &did_id, None, &proof_schema_id)
                    .await
                    .unwrap();

            Self {
                data_layer,
                proof_request_id,
            }
        }
    }

    #[tokio::test]
    async fn reject_proof_request_test_only_offered_state_can_be_rejected() {
        let test_data = TestData::new().await;

        let now = get_dummy_date();
        insert_proof_state(
            &test_data.data_layer.db,
            &test_data.proof_request_id,
            now,
            now,
            ProofRequestState::Created,
        )
        .await
        .unwrap();

        let old_state = get_proof_state(&test_data.data_layer.db, &test_data.proof_request_id)
            .await
            .unwrap();
        assert_eq!(ProofRequestState::Created, old_state);

        let result = test_data
            .data_layer
            .reject_proof_request(&test_data.proof_request_id)
            .await;
        assert!(result.is_err_and(|error| matches!(error, DataLayerError::RecordNotUpdated)));

        let new_state = get_proof_state(&test_data.data_layer.db, &test_data.proof_request_id)
            .await
            .unwrap();
        assert_eq!(ProofRequestState::Created, new_state);

        let later = now.add(Duration::new(1, 0));
        insert_proof_state(
            &test_data.data_layer.db,
            &test_data.proof_request_id,
            later,
            later,
            ProofRequestState::Offered,
        )
        .await
        .unwrap();

        let old_state = get_proof_state(&test_data.data_layer.db, &test_data.proof_request_id)
            .await
            .unwrap();
        assert_eq!(ProofRequestState::Offered, old_state);

        let result = test_data
            .data_layer
            .reject_proof_request(&test_data.proof_request_id)
            .await;
        assert!(result.is_ok());

        let new_state = get_proof_state(&test_data.data_layer.db, &test_data.proof_request_id)
            .await
            .unwrap();
        assert_eq!(ProofRequestState::Rejected, new_state);

        let result = test_data
            .data_layer
            .reject_proof_request(&test_data.proof_request_id)
            .await;
        assert!(result.is_err_and(|error| matches!(error, DataLayerError::RecordNotUpdated)));

        let new_state = get_proof_state(&test_data.data_layer.db, &test_data.proof_request_id)
            .await
            .unwrap();
        assert_eq!(ProofRequestState::Rejected, new_state);
    }
}

use one_core::repository::{data_provider::CredentialShareResponse, error::DataLayerError};
use time::OffsetDateTime;

use crate::{
    common_queries::{get_credential_state, insert_credential_state},
    entity::credential_state,
    OldProvider,
};

impl OldProvider {
    pub async fn share_credential(
        &self,
        credential_id: &str,
    ) -> Result<CredentialShareResponse, DataLayerError> {
        let credential_state = get_credential_state(&self.db, credential_id).await?;

        match credential_state {
            credential_state::CredentialState::Created
            | credential_state::CredentialState::Offered
            | credential_state::CredentialState::Pending => {
                let now = OffsetDateTime::now_utc();

                if credential_state == credential_state::CredentialState::Created {
                    insert_credential_state(
                        &self.db,
                        credential_id,
                        now,
                        credential_state::CredentialState::Offered,
                    )
                    .await?;
                }

                Ok(CredentialShareResponse {
                    credential_id: credential_id.to_string(),
                    transport: "PROCIVIS_TEMPORARY".to_string(),
                })
            }
            _ => Err(DataLayerError::AlreadyExists),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::common_queries::insert_credential_state;
    use crate::test_utilities::*;
    use crate::{
        entity::{credential_state, CredentialState},
        OldProvider,
    };
    use sea_orm::EntityTrait;
    use std::ops::Add;
    use time::{Duration, OffsetDateTime};
    use uuid::Uuid;

    struct TestData {
        pub data_layer: OldProvider,
        pub credential_id: String,
    }

    impl TestData {
        async fn new() -> Self {
            let data_layer = setup_test_data_provider_and_connection().await.unwrap();

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

            let credential_id = insert_credential(&data_layer.db, &credential_schema_id, &did_id)
                .await
                .unwrap();
            let credential_state_count = CredentialState::find()
                .all(&data_layer.db)
                .await
                .unwrap()
                .len();
            assert_eq!(1, credential_state_count);

            Self {
                data_layer,
                credential_id,
            }
        }
    }

    #[tokio::test]
    async fn create_credential_test_simple() {
        let test_data = TestData::new().await;

        let share_credential = test_data
            .data_layer
            .share_credential(&test_data.credential_id)
            .await;
        assert!(share_credential.is_ok());

        let credential_state_count = CredentialState::find()
            .all(&test_data.data_layer.db)
            .await
            .unwrap()
            .len();
        assert_eq!(2, credential_state_count);
    }

    #[tokio::test]
    async fn create_credential_test_share_three_states() {
        let test_data = TestData::new().await;

        let share_credential = test_data
            .data_layer
            .share_credential(&test_data.credential_id)
            .await;
        assert!(share_credential.is_ok());

        let we_can_share_same_credential_many_times = test_data
            .data_layer
            .share_credential(&test_data.credential_id)
            .await;
        assert!(we_can_share_same_credential_many_times.is_ok());

        let now = OffsetDateTime::now_utc();
        insert_credential_state(
            &test_data.data_layer.db,
            &test_data.credential_id,
            now,
            credential_state::CredentialState::Pending,
        )
        .await
        .unwrap();

        let we_can_also_share_in_pending_state = &test_data
            .data_layer
            .share_credential(&test_data.credential_id)
            .await;
        assert!(we_can_also_share_in_pending_state.is_ok());

        let later: OffsetDateTime = now.add(Duration::new(1, 0));
        insert_credential_state(
            &test_data.data_layer.db,
            &test_data.credential_id,
            later,
            credential_state::CredentialState::Error,
        )
        .await
        .unwrap();

        let but_we_cannot_share_it_when_its_state_is_not_correct = test_data
            .data_layer
            .share_credential(&test_data.credential_id)
            .await;
        assert!(but_we_cannot_share_it_when_its_state_is_not_correct.is_err());

        let credential_state_count = CredentialState::find()
            .all(&test_data.data_layer.db)
            .await
            .unwrap()
            .len();
        assert_eq!(4, credential_state_count);
    }
}

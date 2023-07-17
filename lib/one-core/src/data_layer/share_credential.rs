use time::OffsetDateTime;

use crate::data_layer::{
    common_queries::get_credential_state,
    common_queries::insert_credential_state,
    data_model::{CredentialShareResponse, Transport},
    entities::credential_state,
    DataLayer, DataLayerError,
};

impl DataLayer {
    pub async fn share_credential(
        &self,
        credential_id: &str,
    ) -> Result<CredentialShareResponse, DataLayerError> {
        let credential_state = get_credential_state(&self.db, credential_id).await?;

        match credential_state {
            credential_state::CredentialState::Created => {
                let now = OffsetDateTime::now_utc();
                insert_credential_state(
                    &self.db,
                    credential_id,
                    now,
                    credential_state::CredentialState::Offered,
                )
                .await?;

                Ok(CredentialShareResponse {
                    credential_id: credential_id.to_string(),
                    transport: Transport::ProcivisTemporary,
                })
            }
            _ => Err(DataLayerError::AlreadyExists),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::data_layer::{
        entities::{claim_schema::Datatype, CredentialState},
        test_utilities::*,
    };
    use sea_orm::EntityTrait;
    use uuid::Uuid;

    #[tokio::test]
    async fn create_credential_test_simple() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();
        let did_id = insert_did(&data_layer.db, "did name", "test123", &organisation_id)
            .await
            .unwrap();
        let credential_schema_id =
            insert_credential_schema_to_database(&data_layer.db, None, &organisation_id, "test123")
                .await
                .unwrap();
        let new_claims: Vec<(Uuid, bool, u32, Datatype)> = (0..4)
            .map(|i| (Uuid::new_v4(), i % 2 == 0, i, Datatype::String))
            .collect();
        insert_many_claims_schema_to_database(&data_layer.db, &credential_schema_id, &new_claims)
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

        let share_credential = data_layer.share_credential(&credential_id).await;
        assert!(share_credential.is_ok());

        let credential_state_count = CredentialState::find()
            .all(&data_layer.db)
            .await
            .unwrap()
            .len();
        assert_eq!(2, credential_state_count);
    }
}

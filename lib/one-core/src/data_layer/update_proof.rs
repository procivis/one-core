use sea_orm::{ActiveModelTrait, DbErr, Set, Unchanged};
use time::OffsetDateTime;

use crate::data_layer::{DataLayer, DataLayerError};

use super::entities::proof;

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

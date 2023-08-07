use sea_orm::{ActiveModelTrait, DbErr, Set, Unchanged};
use time::OffsetDateTime;

use crate::data_layer::{DataLayer, DataLayerError};

use super::entities::credential;

impl DataLayer {
    pub async fn update_credential_issuer_did(
        &self,
        credential_id: &str,
        issuer: &str,
    ) -> Result<(), DataLayerError> {
        let model = credential::ActiveModel {
            id: Unchanged(credential_id.to_owned()),
            issuer_did_id: Set(issuer.to_owned()),
            last_modified: Set(OffsetDateTime::now_utc()),
            ..Default::default()
        };

        model.update(&self.db).await.map_err(|e| match e {
            DbErr::RecordNotUpdated => DataLayerError::RecordNotUpdated,
            _ => DataLayerError::GeneralRuntimeError(e.to_string()),
        })?;

        Ok(())
    }

    pub async fn update_credential_received_did(
        &self,
        credential_id: &str,
        did_id: &str,
    ) -> Result<(), DataLayerError> {
        let model = credential::ActiveModel {
            id: Unchanged(credential_id.to_owned()),
            receiver_did_id: Set(Some(did_id.to_owned())),
            last_modified: Set(OffsetDateTime::now_utc()),
            ..Default::default()
        };

        model.update(&self.db).await.map_err(|e| match e {
            DbErr::RecordNotUpdated => DataLayerError::RecordNotUpdated,
            _ => DataLayerError::GeneralRuntimeError(e.to_string()),
        })?;

        Ok(())
    }

    pub async fn update_credential_token(
        &self,
        credential_id: &str,
        token: Vec<u8>,
    ) -> Result<(), DataLayerError> {
        let model = credential::ActiveModel {
            id: Unchanged(credential_id.to_owned()),
            credential: Set(token),
            last_modified: Set(OffsetDateTime::now_utc()),
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
    async fn test_update_holder_did() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let credential_schema_id =
            insert_credential_schema_to_database(&data_layer.db, None, &organisation_id, "test123")
                .await
                .unwrap();

        let issuer_did = "did:key:issuer";
        let issuer_did_id = insert_did(&data_layer.db, "DID_NAME", issuer_did, &organisation_id)
            .await
            .unwrap();

        let credential_id =
            insert_credential(&data_layer.db, &credential_schema_id, &issuer_did_id)
                .await
                .unwrap();

        let did = "did:key:123";
        let did_id = insert_did(&data_layer.db, "DID_NAME", did, &organisation_id)
            .await
            .unwrap();

        let result = data_layer
            .update_credential_received_did(&credential_id, &did_id)
            .await;

        assert!(result.is_ok());

        let credential_model = get_credential_by_id(&data_layer.db, &credential_id)
            .await
            .unwrap()
            .expect("Credential doesn't exist");

        assert_eq!(credential_model.receiver_did_id, Some(did_id.to_owned()));
    }

    #[tokio::test]
    async fn test_update_credential_content() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let credential_schema_id =
            insert_credential_schema_to_database(&data_layer.db, None, &organisation_id, "test123")
                .await
                .unwrap();

        let issuer_did = "did:key:issuer";
        let issuer_did_id = insert_did(&data_layer.db, "DID_NAME", issuer_did, &organisation_id)
            .await
            .unwrap();

        let credential_id =
            insert_credential(&data_layer.db, &credential_schema_id, &issuer_did_id)
                .await
                .unwrap();

        let did = "did:key:123";
        let did_id = insert_did(&data_layer.db, "DID_NAME", did, &organisation_id)
            .await
            .unwrap();

        let result = data_layer
            .update_credential_received_did(&credential_id, &did_id)
            .await;

        assert!(result.is_ok());

        let credential_model = get_credential_by_id(&data_layer.db, &credential_id)
            .await
            .unwrap()
            .expect("Credential doesn't exist");

        assert_eq!(credential_model.receiver_did_id, Some(did_id.to_owned()));
        assert_ne!(credential_model.last_modified, get_dummy_date());
    }

    #[tokio::test]
    async fn test_update_credential_token() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let credential_schema_id =
            insert_credential_schema_to_database(&data_layer.db, None, &organisation_id, "test123")
                .await
                .unwrap();

        let issuer_did = "did:key:issuer";
        let issuer_did_id = insert_did(&data_layer.db, "DID_NAME", issuer_did, &organisation_id)
            .await
            .unwrap();

        let credential_id =
            insert_credential(&data_layer.db, &credential_schema_id, &issuer_did_id)
                .await
                .unwrap();

        let token = "token".bytes().collect::<Vec<u8>>();

        let result = data_layer
            .update_credential_token(&credential_id, token.clone())
            .await;

        assert!(result.is_ok());

        let credential_model = get_credential_by_id(&data_layer.db, &credential_id)
            .await
            .unwrap()
            .expect("Credential doesn't exist");

        assert_eq!(credential_model.credential, token);
        assert_ne!(credential_model.last_modified, get_dummy_date());
    }
}

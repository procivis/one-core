use one_core::repository::{data_provider::GetDidDetailsResponse, error::DataLayerError};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use crate::{
    entity::{did, Did},
    OldProvider,
};

impl OldProvider {
    pub async fn get_did_details(
        &self,
        uuid: &str,
    ) -> Result<GetDidDetailsResponse, DataLayerError> {
        let did: did::Model = Did::find_by_id(uuid)
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?
            .ok_or(DataLayerError::RecordNotFound)?;

        Ok(did.into())
    }

    pub async fn get_did_details_by_value(
        &self,
        value: &str,
    ) -> Result<GetDidDetailsResponse, DataLayerError> {
        let did: did::Model = Did::find()
            .filter(did::Column::Did.eq(value))
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?
            .ok_or(DataLayerError::RecordNotFound)?;

        Ok(did.into())
    }
}

#[cfg(test)]
mod tests {
    use one_core::repository::{data_provider::DidType, error::DataLayerError};
    use uuid::Uuid;

    use crate::test_utilities::*;

    #[tokio::test]
    async fn test_get_existing_did() {
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();
        let did_name = "test did name";
        let did = "test:did";
        let id = insert_did(&data_layer.db, did_name, did, &organisation_id)
            .await
            .unwrap();

        let result = data_layer.get_did_details(&id).await;

        assert!(result.is_ok());

        let content = result.unwrap();
        assert_eq!(content.id, id);
        assert_eq!(content.did_method, "KEY");
        assert_eq!(content.did_type, DidType::Local);
        assert_eq!(content.did, did);
        assert_eq!(content.name, did_name);
        assert_eq!(content.organisation_id, organisation_id);
    }

    #[tokio::test]
    async fn test_get_existing_did_by_value() {
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();
        let did_name = "test did name";
        let did = "test:did";
        let id = insert_did(&data_layer.db, did_name, did, &organisation_id)
            .await
            .unwrap();

        let result = data_layer.get_did_details_by_value(did).await;

        assert!(result.is_ok());

        let content = result.unwrap();
        assert_eq!(content.id, id);
        assert_eq!(content.did_method, "KEY");
        assert_eq!(content.did_type, DidType::Local);
        assert_eq!(content.did, did);
        assert_eq!(content.name, did_name);
        assert_eq!(content.organisation_id, organisation_id);
    }

    #[tokio::test]
    async fn test_get_not_existing_did() {
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();

        let id = Uuid::new_v4();

        let result = data_layer.get_did_details(&id.to_string()).await;

        assert!(matches!(result, Err(DataLayerError::RecordNotFound)));
    }
}

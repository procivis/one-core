use crate::{
    entity::{did, Did},
    OldProvider,
};

use one_core::repository::{data_provider::GetDidDetailsResponse, error::DataLayerError};
use sea_orm::{ColumnTrait, Condition, EntityTrait, QueryFilter, QueryOrder};

impl OldProvider {
    pub async fn get_local_dids(
        &self,
        organisation_id: &str,
    ) -> Result<Vec<GetDidDetailsResponse>, DataLayerError> {
        let query = Did::find()
            .filter(
                Condition::all()
                    .add(did::Column::TypeField.eq(did::DidType::Local))
                    .add(did::Column::OrganisationId.eq(organisation_id)),
            )
            .order_by_desc(did::Column::CreatedDate)
            .order_by_desc(did::Column::Id);

        let dids: Vec<did::Model> = query
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        Ok(dids.into_iter().map(|item| item.into()).collect())
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{ActiveModelTrait, Set};
    use uuid::Uuid;

    use crate::{entity::did, test_utilities::*};
    #[tokio::test]
    async fn test_get_one_did() {
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let did_name = "test did name";
        let did = "test:did";
        let id = insert_did(&data_layer.db, did_name, did, &organisation_id)
            .await
            .unwrap();

        let result = data_layer.get_local_dids(&organisation_id).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(1, response.len());
        assert_eq!(id, response[0].id);
    }

    #[tokio::test]
    async fn test_get_empty_result() {
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let result = data_layer.get_local_dids(&organisation_id).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(0, response.len());
    }

    #[tokio::test]
    async fn test_get_empty_different_organisation() {
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let did_name = "test did name";
        let did = "test:did";
        insert_did(&data_layer.db, did_name, did, &organisation_id)
            .await
            .unwrap();

        let result = data_layer.get_local_dids(&Uuid::new_v4().to_string()).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(0, response.len());
    }

    #[tokio::test]
    async fn test_filter_out_remote_did() {
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let did_name = "test did name";
        let did = "test:did";
        let local_did_id = insert_did(&data_layer.db, did_name, did, &organisation_id)
            .await
            .unwrap();

        let _remote_did = did::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            did: Set("did:key:remote".to_string()),
            created_date: Set(get_dummy_date()),
            last_modified: Set(get_dummy_date()),
            name: Set("remote".to_string()),
            type_field: Set(did::DidType::Remote),
            method: Set(did::DidMethod::Key),
            organisation_id: Set(organisation_id.to_owned()),
        }
        .insert(&data_layer.db)
        .await
        .unwrap();

        let result = data_layer.get_local_dids(&organisation_id).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(1, response.len());
        assert_eq!(local_did_id, response[0].id);
    }
}

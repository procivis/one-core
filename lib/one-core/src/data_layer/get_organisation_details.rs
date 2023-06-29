use sea_orm::{EntityTrait, Select};

use crate::data_layer::data_model::GetOrganisationDetailsResponse;
use crate::data_layer::entities::{organisation, Organisation};
use crate::data_layer::{DataLayer, DataLayerError};

impl DataLayer {
    pub async fn get_organisation_details(
        &self,
        uuid: &str,
    ) -> Result<GetOrganisationDetailsResponse, DataLayerError> {
        let organisation: organisation::Model = get_base_query(uuid)
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?
            .ok_or(DataLayerError::RecordNotFound)?;

        Ok(organisation.into())
    }
}

fn get_base_query(uuid: &str) -> Select<Organisation> {
    Organisation::find_by_id(uuid)
}

#[cfg(test)]
mod tests {
    use crate::data_layer::{test_utilities::*, DataLayerError};
    use uuid::Uuid;

    #[tokio::test]
    async fn test_get_organisations() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let org_uuid = Uuid::new_v4();

        insert_organisation_to_database(&data_layer.db, Some(org_uuid))
            .await
            .unwrap();

        let details = data_layer
            .get_organisation_details(&org_uuid.to_string())
            .await;

        assert!(details.is_ok());
        assert_eq!(details.unwrap().id, org_uuid.to_string());
    }

    #[tokio::test]
    async fn test_get_not_existing_organisation() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let org_uuid = Uuid::new_v4();

        let details = data_layer
            .get_organisation_details(&org_uuid.to_string())
            .await;

        assert!(details.is_err());
        assert_eq!(details, Err(DataLayerError::RecordNotFound));
    }
}

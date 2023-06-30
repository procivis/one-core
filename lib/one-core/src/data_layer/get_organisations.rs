use sea_orm::EntityTrait;

use crate::data_layer::data_model::GetOrganisationDetailsResponse;
use crate::data_layer::entities::{organisation, Organisation};
use crate::data_layer::{DataLayer, DataLayerError};

impl DataLayer {
    pub async fn get_organisations(
        &self,
    ) -> Result<Vec<GetOrganisationDetailsResponse>, DataLayerError> {
        let organisations: Vec<organisation::Model> = Organisation::find()
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        Ok(organisations.into_iter().map(|org| org.into()).collect())
    }
}

#[cfg(test)]
mod tests {
    use crate::data_layer::test_utilities::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_get_organisations() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let details = data_layer.get_organisations().await;
        assert!(details.is_ok());
        assert_eq!(details.unwrap().len(), 0);

        let uuid = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];

        insert_organisation_to_database(&data_layer.db, Some(uuid[0]))
            .await
            .unwrap();

        let details = data_layer.get_organisations().await;
        assert!(details.is_ok());
        assert_eq!(details.as_ref().unwrap().len(), 1);
        assert_eq!(details.unwrap()[0].id, uuid[0].to_string());

        insert_organisation_to_database(&data_layer.db, Some(uuid[1]))
            .await
            .unwrap();
        insert_organisation_to_database(&data_layer.db, Some(uuid[2]))
            .await
            .unwrap();

        let details = data_layer.get_organisations().await;
        assert!(details.is_ok());
        assert_eq!(details.as_ref().unwrap().len(), 3);
        assert!(details
            .unwrap()
            .iter()
            .all(|org| uuid.contains(&org.id.parse::<Uuid>().unwrap())));
    }
}

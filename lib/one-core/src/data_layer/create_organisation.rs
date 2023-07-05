use sea_orm::{DbErr, EntityTrait, Set};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::data_layer::entities::organisation;
use crate::data_layer::{DataLayer, DataLayerError};

use crate::data_layer::data_model::{CreateOrganisationRequest, CreateOrganisationResponse};

impl DataLayer {
    pub async fn create_organisation(
        &self,
        request: CreateOrganisationRequest,
    ) -> Result<CreateOrganisationResponse, DataLayerError> {
        let now = OffsetDateTime::now_utc();
        let id = request.id.unwrap_or_else(Uuid::new_v4);

        let organisation = organisation::Entity::insert(organisation::ActiveModel {
            id: Set(id.to_string()),
            created_date: Set(now),
            last_modified: Set(now),
        })
        .exec(&self.db)
        .await
        .map_err(|e| match e {
            DbErr::Exec(e) => {
                tracing::error!("Record not inserted. Error: {e}");
                DataLayerError::AlreadyExists
            }
            e => {
                tracing::error!("Error while creating organisation: {:?}", e);
                DataLayerError::GeneralRuntimeError(e.to_string())
            }
        })?;

        Ok(CreateOrganisationResponse {
            id: organisation.last_insert_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::EntityTrait;
    use uuid::Uuid;

    use super::*;
    use crate::data_layer::{
        entities::Organisation, test_utilities::setup_test_data_layer_and_connection,
    };

    #[tokio::test]
    async fn create_organisation_id_provided() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let org_id = Uuid::new_v4();

        let request = CreateOrganisationRequest { id: Some(org_id) };

        let response = data_layer.create_organisation(request).await;
        assert!(response.is_ok());
        assert_eq!(Uuid::parse_str(&response.unwrap().id).unwrap(), org_id);

        assert_eq!(
            Organisation::find()
                .all(&data_layer.db)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn create_organisation_id_not_provided() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let request = CreateOrganisationRequest { id: None };

        let response = data_layer.create_organisation(request).await;
        assert!(response.is_ok());
        assert!(Uuid::parse_str(&response.unwrap().id).is_ok());

        assert_eq!(
            Organisation::find()
                .all(&data_layer.db)
                .await
                .unwrap()
                .len(),
            1
        );
    }
}

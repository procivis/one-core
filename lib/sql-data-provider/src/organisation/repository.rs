use super::OrganisationProvider;
use crate::{entity::organisation, error_mapper::to_data_layer_error};
use one_core::{
    common_mapper::vector_try_into,
    model::organisation::{Organisation, OrganisationId, OrganisationRelations},
    repository::{error::DataLayerError, organisation_repository::OrganisationRepository},
};
use sea_orm::EntityTrait;
use std::str::FromStr;
use uuid::Uuid;

#[async_trait::async_trait]
impl OrganisationRepository for OrganisationProvider {
    async fn create_organisation(
        &self,
        organisation: Organisation,
    ) -> Result<OrganisationId, DataLayerError> {
        let organisation =
            organisation::Entity::insert(organisation::ActiveModel::from(organisation))
                .exec(&self.db)
                .await
                .map_err(to_data_layer_error)?;

        Uuid::from_str(&organisation.last_insert_id).map_err(|_| DataLayerError::MappingError)
    }

    async fn get_organisation(
        &self,
        id: &OrganisationId,
        _relations: &OrganisationRelations,
    ) -> Result<Organisation, DataLayerError> {
        let organisation = organisation::Entity::find_by_id(id.to_string())
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?
            .ok_or(DataLayerError::RecordNotFound)?;
        organisation.try_into()
    }

    async fn get_organisation_list(&self) -> Result<Vec<Organisation>, DataLayerError> {
        let organisations: Vec<organisation::Model> = organisation::Entity::find()
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        vector_try_into(organisations)
    }
}
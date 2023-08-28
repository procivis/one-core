use std::str::FromStr;

use sea_orm::{EntityTrait, ModelTrait};
use uuid::Uuid;

use one_core::{
    model::{
        did::Did,
        organisation::{Organisation, OrganisationId, OrganisationRelations},
    },
    repository::{error::DataLayerError, organisation_repository::OrganisationRepository},
};

use crate::{
    entity::{did, organisation},
    error_mapper::to_data_layer_error,
};

use super::{mapper::organisation_from_models, OrganisationProvider};

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
        relations: &OrganisationRelations,
    ) -> Result<Organisation, DataLayerError> {
        let organisation = organisation::Entity::find_by_id(id.to_string())
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?
            .ok_or(DataLayerError::RecordNotFound)?;

        let did_list = if let Some(did_relations) = &relations.did {
            let did_models = organisation
                .find_related(did::Entity)
                .all(&self.db)
                .await
                .map_err(to_data_layer_error)?;

            let mut did_list = Vec::with_capacity(did_models.len());
            for model in did_models {
                let did: Did = model.try_into()?;
                let did_details = self.did_repository.get_did(&did.id, did_relations).await?;
                did_list.push(did_details);
            }
            Some(did_list)
        } else {
            None
        };

        organisation_from_models(organisation, did_list)
    }

    async fn get_organisation_list(&self) -> Result<Vec<Organisation>, DataLayerError> {
        let organisations: Vec<organisation::Model> = organisation::Entity::find()
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(organisations
            .into_iter()
            .filter_map(|organisation| organisation_from_models(organisation, None).ok())
            .collect())
    }
}

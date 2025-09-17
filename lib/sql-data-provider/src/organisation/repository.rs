use autometrics::autometrics;
use one_core::model::organisation::{
    Organisation, OrganisationRelations, UpdateOrganisationRequest,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::organisation_repository::OrganisationRepository;
use one_dto_mapper::convert_inner;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use shared_types::OrganisationId;

use super::OrganisationProvider;
use crate::entity::organisation;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};

#[autometrics]
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

        Ok(organisation.last_insert_id)
    }

    async fn update_organisation(
        &self,
        request: UpdateOrganisationRequest,
    ) -> Result<(), DataLayerError> {
        organisation::Entity::update(organisation::ActiveModel::from(request))
            .exec(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;
        Ok(())
    }

    async fn get_organisation(
        &self,
        id: &OrganisationId,
        _relations: &OrganisationRelations,
    ) -> Result<Option<Organisation>, DataLayerError> {
        let organisation = organisation::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(convert_inner(organisation))
    }

    async fn get_organisation_for_wallet_provider(
        &self,
        wallet_provider: &str,
    ) -> Result<Option<Organisation>, DataLayerError> {
        let organisations: Option<organisation::Model> = organisation::Entity::find()
            .filter(organisation::Column::WalletProvider.eq(wallet_provider))
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(convert_inner(organisations))
    }

    async fn get_organisation_list(&self) -> Result<Vec<Organisation>, DataLayerError> {
        let organisations: Vec<organisation::Model> = organisation::Entity::find()
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(convert_inner(organisations))
    }
}

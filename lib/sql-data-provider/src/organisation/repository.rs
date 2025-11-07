use autometrics::autometrics;
use futures::FutureExt;
use one_core::model::organisation::{
    GetOrganisationList, Organisation, OrganisationListQuery, OrganisationRelations,
    UpdateOrganisationRequest,
};
use one_core::proto::transaction_manager::{IsolationLevel, TransactionManager};
use one_core::repository::error::DataLayerError;
use one_core::repository::organisation_repository::OrganisationRepository;
use one_dto_mapper::convert_inner;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use shared_types::OrganisationId;

use super::OrganisationProvider;
use crate::common::list_query_with_base_model;
use crate::entity::organisation;
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error, unpack_data_layer_error};

#[autometrics]
#[async_trait::async_trait]
impl OrganisationRepository for OrganisationProvider {
    async fn create_organisation(
        &self,
        organisation: Organisation,
    ) -> Result<OrganisationId, DataLayerError> {
        let organisation_id = organisation.id;
        self.db
            .transaction_with_config(
                async {
                    organisation::Entity::insert(organisation::ActiveModel::from(organisation))
                        .exec(&self.db)
                        .await
                        .map_err(to_data_layer_error)?;
                    Ok(())
                }
                .boxed(),
                // In isolation mode "read committed" InnoDB will _not_ create gap locks. Given there
                // are multiple unique indexes, this is necessary to avoid deadlocks during parallel
                // inserts.
                Some(IsolationLevel::ReadCommitted),
                None,
            )
            .await?
            .map_err(unpack_data_layer_error)?;
        Ok(organisation_id)
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

    async fn get_organisation_list(
        &self,
        query_params: OrganisationListQuery,
    ) -> Result<GetOrganisationList, DataLayerError> {
        let query = organisation::Entity::find().with_list_query(&query_params);

        list_query_with_base_model(query, query_params, &self.db).await
    }
}

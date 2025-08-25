use autometrics::autometrics;
use one_core::model::wallet_unit::{
    GetWalletUnitList, UpdateWalletUnitRequest, WalletUnit, WalletUnitListQuery,
    WalletUnitRelations,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::wallet_unit_repository::WalletUnitRepository;
use one_dto_mapper::convert_inner;
use sea_orm::{ActiveModelTrait, EntityTrait, PaginatorTrait, Set, Unchanged};
use shared_types::WalletUnitId;
use time::OffsetDateTime;

use super::WalletUnitProvider;
use crate::common::calculate_pages_count;
use crate::entity::wallet_unit;
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};

#[autometrics]
#[async_trait::async_trait]
impl WalletUnitRepository for WalletUnitProvider {
    async fn create_wallet_unit(
        &self,
        request: WalletUnit,
    ) -> Result<WalletUnitId, DataLayerError> {
        let wallet_unit = wallet_unit::ActiveModel::from(request)
            .insert(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(wallet_unit.id)
    }

    async fn get_wallet_unit(
        &self,
        id: &WalletUnitId,
        _relations: &WalletUnitRelations,
    ) -> Result<Option<WalletUnit>, DataLayerError> {
        let wallet_unit = wallet_unit::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(convert_inner(wallet_unit))
    }

    async fn get_wallet_unit_list(
        &self,
        query_params: WalletUnitListQuery,
    ) -> Result<GetWalletUnitList, DataLayerError> {
        let mut query = wallet_unit::Entity::find();

        query = query.with_list_query(&query_params);

        let wallet_units = query.all(&self.db).await.map_err(to_data_layer_error)?;

        let total_items = wallet_unit::Entity::find()
            .with_list_query(&query_params)
            .count(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        let page_size = query_params
            .pagination
            .as_ref()
            .map(|p| p.page_size as u64)
            .unwrap_or(total_items);

        let total_pages = calculate_pages_count(total_items, page_size);

        Ok(GetWalletUnitList {
            values: convert_inner(wallet_units),
            total_pages,
            total_items,
        })
    }

    async fn update_wallet_unit(
        &self,
        id: &WalletUnitId,
        request: UpdateWalletUnitRequest,
    ) -> Result<(), DataLayerError> {
        let update_model = wallet_unit::ActiveModel {
            id: Unchanged(*id),
            last_modified: Set(OffsetDateTime::now_utc()),
            status: request
                .status
                .map(|status| Set(status.into()))
                .unwrap_or_default(),
            ..Default::default()
        };

        update_model
            .update(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;

        Ok(())
    }
}

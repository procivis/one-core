use autometrics::autometrics;
use one_core::model::wallet_unit::{
    GetWalletUnitList, UpdateWalletUnitRequest, WalletUnit, WalletUnitListQuery,
    WalletUnitRelations,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::wallet_unit_repository::WalletUnitRepository;
use one_dto_mapper::try_convert_inner;
use sea_orm::{ActiveModelTrait, EntityTrait, PaginatorTrait, QueryOrder, Set, Unchanged};
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
        let wallet_unit = wallet_unit::ActiveModel::try_from(request)?
            .insert(&self.db.tx())
            .await
            .map_err(to_data_layer_error)?;

        Ok(wallet_unit.id)
    }

    async fn get_wallet_unit(
        &self,
        id: &WalletUnitId,
        relations: &WalletUnitRelations,
    ) -> Result<Option<WalletUnit>, DataLayerError> {
        let Some(wallet_unit) = wallet_unit::Entity::find_by_id(id)
            .one(&self.db.tx())
            .await
            .map_err(to_data_layer_error)?
        else {
            return Ok(None);
        };
        let organisation_id = wallet_unit.organisation_id;
        let mut wallet_unit = WalletUnit::try_from(wallet_unit)?;

        if let Some(org_relations) = &relations.organisation {
            let org = self
                .organisation_repository
                .get_organisation(&organisation_id, org_relations)
                .await?
                .ok_or(DataLayerError::MissingRequiredRelation {
                    relation: "wallet_unit-organisation",
                    id: organisation_id.to_string(),
                })?;
            wallet_unit.organisation = Some(org);
        }
        Ok(Some(wallet_unit))
    }

    async fn get_wallet_unit_list(
        &self,
        query_params: WalletUnitListQuery,
    ) -> Result<GetWalletUnitList, DataLayerError> {
        let mut query = wallet_unit::Entity::find();

        query = query.with_list_query(&query_params);

        if query_params.sorting.is_some() || query_params.pagination.is_some() {
            // fallback ordering
            query = query
                .order_by_desc(wallet_unit::Column::CreatedDate)
                .order_by_desc(wallet_unit::Column::Id);
        }

        let wallet_units = query
            .all(&self.db.tx())
            .await
            .map_err(to_data_layer_error)?;

        let total_items = wallet_unit::Entity::find()
            .with_list_query(&query_params)
            .count(&self.db.tx())
            .await
            .map_err(to_data_layer_error)?;

        let page_size = query_params
            .pagination
            .as_ref()
            .map(|p| p.page_size as u64)
            .unwrap_or(total_items);

        let total_pages = calculate_pages_count(total_items, page_size);

        Ok(GetWalletUnitList {
            values: try_convert_inner(wallet_units)?,
            total_pages,
            total_items,
        })
    }

    async fn update_wallet_unit(
        &self,
        id: &WalletUnitId,
        request: UpdateWalletUnitRequest,
    ) -> Result<(), DataLayerError> {
        let authentication_key_jwk = request
            .authentication_key_jwk
            .map(|pk| serde_json::to_string(&pk))
            .transpose()
            .map_err(|_| DataLayerError::MappingError)?;
        let update_model = wallet_unit::ActiveModel {
            id: Unchanged(*id),
            last_modified: Set(OffsetDateTime::now_utc()),
            status: request
                .status
                .map(|status| Set(status.into()))
                .unwrap_or_default(),
            last_issuance: request
                .last_issuance
                .map(|last_issuance| Set(last_issuance.into()))
                .unwrap_or_default(),
            authentication_key_jwk: authentication_key_jwk
                .map(|key| Set(Some(key)))
                .unwrap_or_default(),
            ..Default::default()
        };

        update_model
            .update(&self.db.tx())
            .await
            .map_err(to_update_data_layer_error)?;

        Ok(())
    }

    async fn delete_wallet_unit(&self, id: &WalletUnitId) -> Result<(), DataLayerError> {
        wallet_unit::Entity::delete_by_id(id)
            .exec(&self.db.tx())
            .await
            .map_err(to_update_data_layer_error)?;
        Ok(())
    }
}

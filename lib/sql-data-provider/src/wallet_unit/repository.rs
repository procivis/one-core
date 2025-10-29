use autometrics::autometrics;
use futures::FutureExt;
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
use crate::mapper::{to_data_layer_error, to_update_data_layer_error, unpack_data_layer_error};

#[autometrics]
#[async_trait::async_trait]
impl WalletUnitRepository for WalletUnitProvider {
    async fn create_wallet_unit(
        &self,
        request: WalletUnit,
    ) -> Result<WalletUnitId, DataLayerError> {
        let attested_keys = request.attested_keys.clone();
        let mut wallet_unit_id = None;
        self.tx_manager
            .transaction(
                async {
                    let wallet_unit = wallet_unit::ActiveModel::try_from(request)?
                        .insert(&self.db.tx())
                        .await
                        .map_err(to_data_layer_error)?;
                    if let Some(attested_keys) = attested_keys {
                        for key in attested_keys {
                            self.wallet_unit_attested_key_repository
                                .create_attested_key(key.clone())
                                .await?;
                        }
                    }
                    wallet_unit_id = Some(wallet_unit.id);
                    Ok(())
                }
                .boxed(),
            )
            .await?
            .map_err(unpack_data_layer_error)?;
        wallet_unit_id.ok_or(DataLayerError::TransactionError(
            "Missing transaction result".to_string(),
        ))
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

        if let Some(attested_key_relations) = &relations.attested_keys {
            let attested_keys = self
                .wallet_unit_attested_key_repository
                .get_by_wallet_unit_id(wallet_unit.id, attested_key_relations)
                .await?;
            wallet_unit.attested_keys = Some(attested_keys);
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

        self.tx_manager
            .transaction(
                async {
                    update_model
                        .update(&self.db.tx())
                        .await
                        .map_err(to_update_data_layer_error)?;

                    if let Some(attested_keys) = request.attested_keys {
                        // Currently deletion is not supported. New entries are inserted, or updated if already
                        // existing.
                        for key in attested_keys {
                            let result = self
                                .wallet_unit_attested_key_repository
                                .create_attested_key(key.clone())
                                .await;
                            if let Err(err) = result {
                                match err {
                                    DataLayerError::AlreadyExists => {
                                        self.wallet_unit_attested_key_repository
                                            .update_attested_key(key)
                                            .await?
                                    }
                                    err => return Err(err.into()),
                                }
                            }
                        }
                    }
                    Ok(())
                }
                .boxed(),
            )
            .await?
            .map_err(|err| DataLayerError::TransactionError(err.to_string()))?;
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

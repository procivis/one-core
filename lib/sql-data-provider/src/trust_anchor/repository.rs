use autometrics::autometrics;
use one_core::model::trust_anchor::TrustAnchor;
use one_core::repository::error::DataLayerError;
use one_core::repository::trust_anchor_repository::TrustAnchorRepository;
use one_core::service::trust_anchor::dto::{GetTrustAnchorsResponseDTO, ListTrustAnchorsQueryDTO};
use one_dto_mapper::convert_inner;
use sea_orm::prelude::Expr;
use sea_orm::sea_query::{Alias, Func};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, TransactionTrait,
};
use shared_types::TrustAnchorId;

use super::TrustAnchorProvider;
use crate::common::calculate_pages_count;
use crate::entity::{trust_anchor, trust_entity};
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::to_data_layer_error;
use crate::trust_anchor::entities::TrustAnchorsListItemEntityModel;

#[autometrics]
#[async_trait::async_trait]
impl TrustAnchorRepository for TrustAnchorProvider {
    async fn create(&self, anchor: TrustAnchor) -> Result<TrustAnchorId, DataLayerError> {
        let anchor: trust_anchor::ActiveModel = anchor.into();
        let result = anchor.insert(&self.db).await.map_err(to_data_layer_error)?;

        Ok(result.id)
    }

    async fn get(&self, id: TrustAnchorId) -> Result<Option<TrustAnchor>, DataLayerError> {
        let trust_anchor = trust_anchor::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(trust_anchor.map(TrustAnchor::from))
    }

    async fn list(
        &self,
        filters: ListTrustAnchorsQueryDTO,
    ) -> Result<GetTrustAnchorsResponseDTO, DataLayerError> {
        let limit = filters
            .pagination
            .as_ref()
            .map(|pagination| pagination.page_size as _);

        let query = trust_anchor::Entity::find()
            .left_join(trust_entity::Entity)
            .expr_as(
                Func::cast_as(
                    Func::count(Expr::col((trust_entity::Entity, trust_entity::Column::Id))),
                    Alias::new("UNSIGNED"),
                ),
                "entities",
            )
            .group_by(trust_anchor::Column::Id)
            .with_list_query(&filters)
            .order_by_desc(trust_anchor::Column::CreatedDate)
            .order_by_desc(trust_anchor::Column::Id);

        let items_count = query
            .to_owned()
            .count(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        let trust_anchors = query
            .into_model::<TrustAnchorsListItemEntityModel>()
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(GetTrustAnchorsResponseDTO {
            values: convert_inner(trust_anchors),
            total_pages: calculate_pages_count(items_count, limit.unwrap_or(0)),
            total_items: items_count,
        })
    }

    async fn delete(&self, id: TrustAnchorId) -> Result<(), DataLayerError> {
        let tx = self.db.begin().await.map_err(to_data_layer_error)?;

        trust_entity::Entity::delete_many()
            .filter(trust_entity::Column::TrustAnchorId.eq(id))
            .exec(&tx)
            .await
            .map_err(to_data_layer_error)?;

        trust_anchor::Entity::delete_by_id(id)
            .exec(&tx)
            .await
            .map_err(to_data_layer_error)?;

        tx.commit().await.map_err(to_data_layer_error)?;

        Ok(())
    }
}

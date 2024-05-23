use autometrics::autometrics;
use dto_mapper::convert_inner;
use migration::{Alias, Expr, Func};
use one_core::model::trust_anchor::TrustAnchor;
use one_core::repository::error::DataLayerError;
use one_core::repository::trust_anchor_repository::TrustAnchorRepository;
use one_core::service::trust_anchor::dto::{GetTrustAnchorsResponseDTO, ListTrustAnchorsQueryDTO};
use sea_orm::{
    ActiveModelTrait, EntityTrait, JoinType, PaginatorTrait, QueryOrder, QuerySelect, Related, Set,
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
        let value = trust_anchor::ActiveModel {
            id: Set(anchor.id),
            created_date: Set(anchor.created_date),
            last_modified: Set(anchor.last_modified),
            name: Set(anchor.name),
            type_field: Set(anchor.type_field),
            publisher_reference: Set(anchor.publisher_reference),
            role: Set(anchor.role.into()),
            priority: Set(anchor.priority),
            organisation_id: Set(anchor.organisation_id),
        }
        .insert(&self.db)
        .await
        .map_err(to_data_layer_error)?;

        Ok(value.id)
    }

    async fn get(&self, id: TrustAnchorId) -> Result<Option<TrustAnchor>, DataLayerError> {
        let model = trust_anchor::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?
            .map(Into::into);

        Ok(model)
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
            .expr_as_(
                Func::cast_as(
                    Func::count(Expr::col((trust_entity::Entity, trust_entity::Column::Id))),
                    Alias::new("UNSIGNED"),
                ),
                "entities",
            )
            .join_rev(JoinType::LeftJoin, trust_entity::Entity::to())
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
}

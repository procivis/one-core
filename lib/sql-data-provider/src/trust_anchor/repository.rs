use autometrics::autometrics;
use dto_mapper::convert_inner;
use migration::{Alias, Expr, Func};
use one_core::model::trust_anchor::{TrustAnchor, TrustAnchorRelations};
use one_core::repository::error::DataLayerError;
use one_core::repository::trust_anchor_repository::TrustAnchorRepository;
use one_core::service::trust_anchor::dto::{GetTrustAnchorsResponseDTO, ListTrustAnchorsQueryDTO};
use sea_orm::{
    ActiveModelTrait, EntityTrait, JoinType, PaginatorTrait, QueryOrder, QuerySelect, Related,
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
        let anchor: trust_anchor::ActiveModel = anchor.clone().try_into()?;
        let result = anchor.insert(&self.db).await.map_err(to_data_layer_error)?;

        Ok(result.id)
    }

    async fn get(
        &self,
        id: TrustAnchorId,
        relations: &TrustAnchorRelations,
    ) -> Result<Option<TrustAnchor>, DataLayerError> {
        let anchor_model = trust_anchor::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        let Some(anchor_model) = anchor_model else {
            return Ok(None);
        };

        let organisation_id = anchor_model.organisation_id.to_owned();

        let mut anchor = TrustAnchor::from(anchor_model);

        if let Some(organisation_relations) = &relations.organisation {
            anchor.organisation = Some(
                self.organisation_repository
                    .get_organisation(&organisation_id, organisation_relations)
                    .await?
                    .ok_or(DataLayerError::MissingRequiredRelation {
                        relation: "trust_anchor-organisation",
                        id: organisation_id.to_string(),
                    })?,
            );
        }

        Ok(Some(anchor))
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

    async fn delete(&self, id: TrustAnchorId) -> Result<(), DataLayerError> {
        trust_anchor::Entity::delete_by_id(id)
            .exec(&self.db)
            .await
            .map_err(to_data_layer_error)
            .map(|_| ())
    }
}

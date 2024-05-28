use autometrics::autometrics;
use dto_mapper::convert_inner;
use one_core::{
    model::trust_entity::{TrustEntity, TrustEntityRelations},
    repository::{error::DataLayerError, trust_entity_repository::TrustEntityRepository},
    service::trust_entity::dto::{GetTrustEntitiesResponseDTO, ListTrustEntitiesQueryDTO},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, RelationTrait, Set,
};
use shared_types::{TrustAnchorId, TrustEntityId};

use crate::{
    common::calculate_pages_count,
    entity::{trust_anchor, trust_entity},
    list_query_generic::SelectWithListQuery,
    mapper::to_data_layer_error,
    trust_entity::model::TrustEntityListItemEntityModel,
};

use super::TrustEntityProvider;

#[autometrics]
#[async_trait::async_trait]
impl TrustEntityRepository for TrustEntityProvider {
    async fn create(&self, entity: TrustEntity) -> Result<TrustEntityId, DataLayerError> {
        let trust_anchor = entity.trust_anchor.ok_or(DataLayerError::MappingError)?;

        let value = trust_entity::ActiveModel {
            id: Set(entity.id),
            created_date: Set(entity.created_date),
            last_modified: Set(entity.last_modified),
            entity_id: Set(entity.entity_id),
            name: Set(entity.name),
            logo: Set(entity.logo),
            website: Set(entity.website),
            terms_url: Set(entity.terms_url),
            privacy_url: Set(entity.privacy_url),
            role: Set(entity.role.into()),
            trust_anchor_id: Set(trust_anchor.id),
        }
        .insert(&self.db)
        .await
        .map_err(to_data_layer_error)?;

        Ok(value.id)
    }

    async fn get_by_trust_anchor_id(
        &self,
        trust_anchor_id: TrustAnchorId,
    ) -> Result<Vec<TrustEntity>, DataLayerError> {
        let entities = trust_entity::Entity::find()
            .filter(trust_entity::Column::TrustAnchorId.eq(trust_anchor_id))
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(entities.into_iter().map(Into::into).collect())
    }

    async fn delete(&self, id: TrustEntityId) -> Result<(), DataLayerError> {
        trust_entity::Entity::delete_by_id(id)
            .exec(&self.db)
            .await
            .map(|_| ())
            .map_err(to_data_layer_error)
    }

    async fn get(
        &self,
        id: TrustEntityId,
        relations: &TrustEntityRelations,
    ) -> Result<Option<TrustEntity>, DataLayerError> {
        let entity_model = trust_entity::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        let Some(entity_model) = entity_model else {
            return Ok(None);
        };

        let trust_anchor_id = entity_model.trust_anchor_id.to_owned();

        let mut trust_entity = TrustEntity::from(entity_model);

        if let Some(trust_anchor_relations) = &relations.trust_anchor {
            trust_entity.trust_anchor = Some(
                self.trust_anchor_repository
                    .get(trust_anchor_id, trust_anchor_relations)
                    .await?
                    .ok_or(DataLayerError::MissingRequiredRelation {
                        relation: "trust_entity-trust_anchor",
                        id: trust_anchor_id.to_string(),
                    })?,
            );
        }

        Ok(Some(trust_entity))
    }

    async fn list(
        &self,
        filters: ListTrustEntitiesQueryDTO,
    ) -> Result<GetTrustEntitiesResponseDTO, DataLayerError> {
        let limit = filters
            .pagination
            .as_ref()
            .map(|pagination| pagination.page_size as _);

        let query = trust_entity::Entity::find()
            .select_only()
            .columns([
                trust_entity::Column::Id,
                trust_entity::Column::CreatedDate,
                trust_entity::Column::LastModified,
                trust_entity::Column::EntityId,
                trust_entity::Column::Name,
                trust_entity::Column::Logo,
                trust_entity::Column::Website,
                trust_entity::Column::TermsUrl,
                trust_entity::Column::PrivacyUrl,
                trust_entity::Column::Role,
                trust_entity::Column::TrustAnchorId,
            ])
            .column_as(trust_anchor::Column::OrganisationId, "organisation_id")
            .join(
                sea_orm::JoinType::LeftJoin,
                trust_entity::Relation::TrustAnchor.def(),
            )
            .with_list_query(&filters)
            .order_by_desc(trust_entity::Column::CreatedDate)
            .order_by_desc(trust_entity::Column::Id);

        let items_count = query
            .to_owned()
            .count(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        let trust_entities = query
            .into_model::<TrustEntityListItemEntityModel>()
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(GetTrustEntitiesResponseDTO {
            values: convert_inner(trust_entities),
            total_pages: calculate_pages_count(items_count, limit.unwrap_or(0)),
            total_items: items_count,
        })
    }
}

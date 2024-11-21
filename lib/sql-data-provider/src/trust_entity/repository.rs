use autometrics::autometrics;
use one_core::model::trust_entity::{TrustEntity, TrustEntityRelations};
use one_core::repository::error::DataLayerError;
use one_core::repository::trust_entity_repository::TrustEntityRepository;
use one_core::service::trust_entity::dto::{
    GetTrustEntitiesResponseDTO, ListTrustEntitiesQueryDTO,
};
use one_dto_mapper::convert_inner;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, Set,
};
use shared_types::{TrustAnchorId, TrustEntityId};

use super::TrustEntityProvider;
use crate::common::calculate_pages_count;
use crate::entity::trust_entity;
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::to_data_layer_error;
use crate::trust_entity::model::TrustEntityListItemEntityModel;

#[autometrics]
#[async_trait::async_trait]
impl TrustEntityRepository for TrustEntityProvider {
    async fn create(&self, entity: TrustEntity) -> Result<TrustEntityId, DataLayerError> {
        let trust_anchor = entity.trust_anchor.ok_or(DataLayerError::MappingError)?;
        let did = entity.did.ok_or(DataLayerError::MappingError)?;

        let value = trust_entity::ActiveModel {
            id: Set(entity.id),
            created_date: Set(entity.created_date),
            last_modified: Set(entity.last_modified),
            name: Set(entity.name),
            logo: Set(entity.logo.map(String::into_bytes)),
            website: Set(entity.website),
            terms_url: Set(entity.terms_url),
            privacy_url: Set(entity.privacy_url),
            role: Set(entity.role.into()),
            state: Set(entity.state.into()),
            trust_anchor_id: Set(trust_anchor.id),
            did_id: Set(did.id),
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
        let did = entity_model.did_id.to_owned();

        let mut trust_entity = TrustEntity::from(entity_model);

        if relations.trust_anchor.is_some() {
            trust_entity.trust_anchor = Some(
                self.trust_anchor_repository
                    .get(trust_anchor_id)
                    .await?
                    .ok_or(DataLayerError::MissingRequiredRelation {
                        relation: "trust_entity-trust_anchor",
                        id: trust_anchor_id.to_string(),
                    })?,
            );
        }

        if let Some(did_relations) = &relations.did {
            trust_entity.did = Some(
                self.did_repository
                    .get_did(&did, did_relations)
                    .await?
                    .ok_or(DataLayerError::MissingRequiredRelation {
                        relation: "trust_entity-did",
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
                trust_entity::Column::Name,
                trust_entity::Column::Logo,
                trust_entity::Column::Website,
                trust_entity::Column::TermsUrl,
                trust_entity::Column::PrivacyUrl,
                trust_entity::Column::Role,
                trust_entity::Column::State,
                trust_entity::Column::TrustAnchorId,
                trust_entity::Column::DidId,
            ])
            .inner_join(crate::entity::trust_anchor::Entity)
            .inner_join(crate::entity::did::Entity)
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

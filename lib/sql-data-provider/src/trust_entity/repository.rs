use autometrics::autometrics;
use one_core::model::trust_entity::{TrustEntity, TrustEntityRelations, UpdateTrustEntityRequest};
use one_core::repository::error::DataLayerError;
use one_core::repository::trust_entity_repository::TrustEntityRepository;
use one_core::service::trust_entity::dto::{
    GetTrustEntitiesResponseDTO, ListTrustEntitiesQueryDTO,
};
use one_dto_mapper::{convert_inner, try_convert_inner};
use sea_orm::prelude::Expr;
use sea_orm::sea_query::IntoCondition;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, JoinType, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, Set, Unchanged,
};
use shared_types::{TrustAnchorId, TrustEntityId};
use time::OffsetDateTime;

use super::TrustEntityProvider;
use crate::common::calculate_pages_count;
use crate::entity::trust_entity::{TrustEntityRole, TrustEntityState};
use crate::entity::{did, organisation, trust_anchor, trust_entity};
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};
use crate::trust_entity::model::TrustEntityListItemEntityModel;

#[autometrics]
#[async_trait::async_trait]
impl TrustEntityRepository for TrustEntityProvider {
    async fn create(&self, entity: TrustEntity) -> Result<TrustEntityId, DataLayerError> {
        let trust_anchor = entity.trust_anchor.ok_or(DataLayerError::MappingError)?;

        let value = trust_entity::ActiveModel {
            id: Set(entity.id),
            created_date: Set(entity.created_date),
            last_modified: Set(entity.last_modified),
            deactivated_at: Set(entity.deactivated_at),
            name: Set(entity.name),
            logo: Set(entity.logo.map(String::into_bytes)),
            website: Set(entity.website),
            terms_url: Set(entity.terms_url),
            privacy_url: Set(entity.privacy_url),
            role: Set(entity.role.into()),
            state: Set(entity.state.into()),
            r#type: Set(entity.r#type.into()),
            content: Set(entity.content),
            entity_key: Set(entity.entity_key),
            trust_anchor_id: Set(trust_anchor.id),
            organisation_id: Set(entity.organisation.map(|org| org.id)),
        }
        .insert(&self.db)
        .await
        .map_err(to_data_layer_error)?;

        Ok(value.id)
    }

    async fn get_by_entity_key(
        &self,
        entity_key: String,
    ) -> Result<Option<TrustEntity>, DataLayerError> {
        let Some((entity_model, trust_anchor)) = trust_entity::Entity::find()
            .filter(trust_entity::Column::EntityKey.eq(entity_key))
            .find_also_related(trust_anchor::Entity)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?
        else {
            return Ok(None);
        };

        let mut entity = TrustEntity::from(entity_model);
        entity.trust_anchor = trust_anchor.map(Into::into);

        Ok(Some(entity))
    }

    async fn get_by_entity_key_and_trust_anchor_id(
        &self,
        entity_key: String,
        trust_anchor_id: TrustAnchorId,
    ) -> Result<Option<TrustEntity>, DataLayerError> {
        let Some((entity_model, trust_anchor)) = trust_entity::Entity::find()
            .filter(trust_entity::Column::EntityKey.eq(entity_key))
            .filter(trust_entity::Column::TrustAnchorId.eq(trust_anchor_id))
            .find_also_related(trust_anchor::Entity)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?
        else {
            return Ok(None);
        };

        let mut entity = TrustEntity::from(entity_model);
        entity.trust_anchor = trust_anchor.map(Into::into);

        Ok(Some(entity))
    }

    async fn get_active_by_trust_anchor_id(
        &self,
        trust_anchor_id: TrustAnchorId,
    ) -> Result<Vec<TrustEntity>, DataLayerError> {
        let entities: Vec<(trust_entity::Model, Option<organisation::Model>)> =
            trust_entity::Entity::find()
                .filter(
                    trust_entity::Column::TrustAnchorId
                        .eq(trust_anchor_id)
                        .and(trust_entity::Column::State.eq(TrustEntityState::Active)),
                )
                .find_also_related(organisation::Entity)
                .all(&self.db)
                .await
                .map_err(to_data_layer_error)?;

        Ok(entities
            .into_iter()
            .map(|(entity_model, organisation_model)| {
                let mut trust_entity_dto = TrustEntity::from(entity_model);
                trust_entity_dto.organisation = convert_inner(organisation_model);
                trust_entity_dto
            })
            .collect())
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
        let organisation_id = entity_model.organisation_id.to_owned();

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

        if let Some(organisation_id) = organisation_id {
            if let Some(organisation_relations) = &relations.organisation {
                trust_entity.organisation = Some(
                    self.organisation_repository
                        .get_organisation(&organisation_id, organisation_relations)
                        .await?
                        .ok_or(DataLayerError::MissingRequiredRelation {
                            relation: "trust_entity-organisation",
                            id: trust_anchor_id.to_string(),
                        })?,
                );
            }
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
                trust_entity::Column::OrganisationId,
                trust_entity::Column::EntityKey,
                trust_entity::Column::Content,
                trust_entity::Column::Type,
            ])
            .inner_join(trust_anchor::Entity)
            .column_as(
                trust_anchor::Column::CreatedDate,
                "trust_anchor_created_date",
            )
            .column_as(
                trust_anchor::Column::LastModified,
                "trust_anchor_last_modified",
            )
            .column_as(trust_anchor::Column::Name, "trust_anchor_name")
            .column_as(trust_anchor::Column::Type, "trust_anchor_type")
            .column_as(
                trust_anchor::Column::PublisherReference,
                "trust_anchor_publisher_reference",
            )
            .column_as(
                trust_anchor::Column::IsPublisher,
                "trust_anchor_is_publisher",
            )
            .join(
                JoinType::LeftJoin,
                trust_entity::Entity::belongs_to(did::Entity)
                    .from(trust_entity::Column::EntityKey)
                    .to(did::Column::Did)
                    .on_condition(|left, right| {
                        let did_org_id = (left, did::Column::OrganisationId);
                        let trust_entity_org_id = (right, trust_entity::Column::OrganisationId);
                        Expr::col(did_org_id.clone())
                            .is_not_null()
                            .and(Expr::col(trust_entity_org_id.clone()).is_not_null())
                            .or(Expr::col(did_org_id).equals(trust_entity_org_id))
                            .into_condition()
                    })
                    .into(),
            )
            .column_as(did::Column::Id, "did_id")
            .column_as(did::Column::Did, "did")
            .column_as(did::Column::CreatedDate, "did_created_date")
            .column_as(did::Column::LastModified, "did_last_modified")
            .column_as(did::Column::Name, "did_name")
            .column_as(did::Column::TypeField, "did_type")
            .column_as(did::Column::Method, "did_method")
            .column_as(did::Column::Deactivated, "did_deactivated")
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
            values: try_convert_inner(trust_entities)?,
            total_pages: calculate_pages_count(items_count, limit.unwrap_or(0)),
            total_items: items_count,
        })
    }

    async fn update(
        &self,
        id: TrustEntityId,
        request: UpdateTrustEntityRequest,
    ) -> Result<(), DataLayerError> {
        let role = match request.role {
            None => Unchanged(TrustEntityRole::Issuer),
            Some(role) => Set(TrustEntityRole::from(role)),
        };
        let state = match request.state {
            None => Unchanged(TrustEntityState::Active),
            Some(state) => Set(TrustEntityState::from(state)),
        };

        let _value = trust_entity::ActiveModel {
            id: Unchanged(id),
            last_modified: Set(OffsetDateTime::now_utc()),
            name: option_to_active_value(request.name),
            logo: option_to_active_value(request.logo.map(|f| f.map(|v| v.into_bytes()))),
            website: option_to_active_value(request.website),
            terms_url: option_to_active_value(request.terms_url),
            privacy_url: option_to_active_value(request.privacy_url),
            role,
            state,
            ..Default::default()
        }
        .update(&self.db)
        .await
        .map_err(to_update_data_layer_error)?;

        Ok(())
    }
}

fn option_to_active_value<T>(param: Option<T>) -> sea_orm::ActiveValue<T>
where
    sea_orm::Value: From<T>,
    T: Default,
{
    match param {
        None => Unchanged(Default::default()),
        Some(value) => Set(value),
    }
}

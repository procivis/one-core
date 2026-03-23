use autometrics::autometrics;
use one_core::model::trust_list_subscription::{
    GetTrustListSubscriptionList, TrustListSubscription, TrustListSubscriptionListQuery,
    TrustListSubscriptionRelations, TrustListSubscriptionState,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::trust_list_subscription_repository::TrustListSubscriptionRepository;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set, Unchanged,
};
use shared_types::TrustListSubscriptionId;
use time::OffsetDateTime;

use super::TrustListSubscriptionProvider;
use crate::common::list_query_with_base_model;
use crate::entity::trust_list_subscription;
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};

#[autometrics]
#[async_trait::async_trait]
impl TrustListSubscriptionRepository for TrustListSubscriptionProvider {
    async fn create(
        &self,
        entity: TrustListSubscription,
    ) -> Result<TrustListSubscriptionId, DataLayerError> {
        let id = entity.id;
        let model: trust_list_subscription::ActiveModel = entity.into();
        model.insert(&self.db).await.map_err(to_data_layer_error)?;
        Ok(id)
    }

    async fn update_state(
        &self,
        id: TrustListSubscriptionId,
        state: TrustListSubscriptionState,
    ) -> Result<(), DataLayerError> {
        trust_list_subscription::Entity::update(trust_list_subscription::ActiveModel {
            id: Unchanged(id),
            last_modified: Set(OffsetDateTime::now_utc()),
            state: Set(state.into()),
            ..Default::default()
        })
        .exec(&self.db)
        .await
        .map_err(to_update_data_layer_error)?;
        Ok(())
    }

    async fn get(
        &self,
        id: &TrustListSubscriptionId,
        relations: &TrustListSubscriptionRelations,
    ) -> Result<Option<TrustListSubscription>, DataLayerError> {
        let subscription = trust_list_subscription::Entity::find_by_id(*id)
            .filter(trust_list_subscription::Column::DeactivatedAt.is_null())
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        let Some(subscription) = subscription else {
            return Ok(None);
        };

        let trust_collection_id = subscription.trust_collection_id;
        let mut result = TrustListSubscription::from(subscription);

        if let Some(trust_collection_relations) = &relations.trust_collection {
            result.trust_collection = Some(
                self.trust_collection_repository
                    .get(&trust_collection_id, trust_collection_relations)
                    .await?
                    .ok_or(DataLayerError::MissingRequiredRelation {
                        relation: "trust_list_subscription-trust_collection",
                        id: trust_collection_id.to_string(),
                    })?,
            );
        }
        Ok(Some(result))
    }

    async fn list(
        &self,
        query: TrustListSubscriptionListQuery,
    ) -> Result<GetTrustListSubscriptionList, DataLayerError> {
        let db_query = trust_list_subscription::Entity::find()
            .filter(trust_list_subscription::Column::DeactivatedAt.is_null())
            .with_list_query(&query)
            .order_by_desc(trust_list_subscription::Column::CreatedDate)
            .order_by_desc(trust_list_subscription::Column::Id);

        list_query_with_base_model(db_query, query, &self.db).await
    }

    async fn delete(&self, id: TrustListSubscriptionId) -> Result<(), DataLayerError> {
        let now = OffsetDateTime::now_utc();

        trust_list_subscription::Entity::update(trust_list_subscription::ActiveModel {
            id: Unchanged(id),
            last_modified: Set(now),
            deactivated_at: Set(Some(now)),
            ..Default::default()
        })
        .exec(&self.db)
        .await
        .map_err(to_update_data_layer_error)?;

        Ok(())
    }

    async fn delete_many(&self, ids: Vec<TrustListSubscriptionId>) -> Result<(), DataLayerError> {
        let now = OffsetDateTime::now_utc();

        trust_list_subscription::Entity::update_many()
            .filter(trust_list_subscription::Column::Id.is_in(ids))
            .set(trust_list_subscription::ActiveModel {
                last_modified: Set(now),
                deactivated_at: Set(Some(now)),
                ..Default::default()
            })
            .exec(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;

        Ok(())
    }
}

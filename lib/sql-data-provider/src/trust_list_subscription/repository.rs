use autometrics::autometrics;
use one_core::model::trust_list_subscription::{
    GetTrustListSubscriptionList, TrustListSubscription, TrustListSubscriptionListQuery,
    TrustListSubscriptionState,
};
use one_core::repository::error::{DataLayerError, EntityKind};
use one_core::repository::trust_list_subscription_repository::TrustListSubscriptionRepository;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, Set,
    Unchanged,
};
use shared_types::TrustListSubscriptionId;

use super::TrustListSubscriptionProvider;
use super::mapper::trust_list_subscription_from_model;
use crate::common::list_query_with_custom_model;
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
            last_modified: Set(one_core::clock::now_utc()),
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
    ) -> Result<TrustListSubscription, DataLayerError> {
        let subscription = trust_list_subscription::Entity::find_by_id(*id)
            .filter(trust_list_subscription::Column::DeactivatedAt.is_null())
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?
            .ok_or_else(|| DataLayerError::EntityNotFound {
                kind: EntityKind::TrustListSubscription,
                id: (*id).into(),
            })?;

        Ok(trust_list_subscription_from_model(
            subscription,
            &self.trust_collection_repository,
        ))
    }

    async fn list(
        &self,
        query: TrustListSubscriptionListQuery,
    ) -> Result<GetTrustListSubscriptionList, DataLayerError> {
        let db_query = trust_list_subscription::Entity::find()
            .filter(trust_list_subscription::Column::DeactivatedAt.is_null())
            .with_list_query(&query, self.db.get_database_backend())
            .order_by_desc(trust_list_subscription::Column::CreatedDate)
            .order_by_desc(trust_list_subscription::Column::Id);

        list_query_with_custom_model(db_query, query, &self.db, |model| {
            Ok(trust_list_subscription_from_model(
                model,
                &self.trust_collection_repository,
            ))
        })
        .await
    }

    async fn delete(&self, id: TrustListSubscriptionId) -> Result<(), DataLayerError> {
        let now = one_core::clock::now_utc();

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
        let now = one_core::clock::now_utc();

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

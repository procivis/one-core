use autometrics::autometrics;
use futures::FutureExt;
use one_core::model::trust_collection::{
    GetTrustCollectionList, TrustCollection, TrustCollectionListQuery,
};
use one_core::repository::error::{DataLayerError, EntityKind};
use one_core::repository::trust_collection_repository::TrustCollectionRepository;
use sea_orm::prelude::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, Set,
    Unchanged,
};
use shared_types::TrustCollectionId;

use super::TrustCollectionProvider;
use super::mapper::trust_collection_from_model;
use crate::common::list_query_with_custom_model;
use crate::entity::{trust_collection, trust_list_subscription};
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};

#[autometrics]
#[async_trait::async_trait]
impl TrustCollectionRepository for TrustCollectionProvider {
    async fn create(&self, entity: TrustCollection) -> Result<TrustCollectionId, DataLayerError> {
        let id = entity.id;
        let model: trust_collection::ActiveModel = entity.into();
        model.insert(&self.db).await.map_err(to_data_layer_error)?;
        Ok(id)
    }

    async fn get(&self, id: &TrustCollectionId) -> Result<TrustCollection, DataLayerError> {
        let trust_collection = trust_collection::Entity::find_by_id(*id)
            .filter(trust_collection::Column::DeactivatedAt.is_null())
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?
            .ok_or_else(|| DataLayerError::EntityNotFound {
                kind: EntityKind::TrustCollection,
                id: (*id).into(),
            })?;

        trust_collection_from_model(trust_collection, &self.organisation_repository)
    }

    async fn list(
        &self,
        query: TrustCollectionListQuery,
    ) -> Result<GetTrustCollectionList, DataLayerError> {
        let db_query = trust_collection::Entity::find()
            .filter(trust_collection::Column::DeactivatedAt.is_null())
            .with_list_query(&query, self.db.get_database_backend())
            .order_by_desc(trust_collection::Column::CreatedDate)
            .order_by_desc(trust_collection::Column::Id);

        list_query_with_custom_model(db_query, query, &self.db, |model| {
            trust_collection_from_model(model, &self.organisation_repository)
        })
        .await
    }

    async fn delete(&self, id: TrustCollectionId) -> Result<(), DataLayerError> {
        self.db
            .tx(async {
                // First soft delete all subscriptions
                let now = one_core::clock::now_utc();
                trust_list_subscription::Entity::update_many()
                    .col_expr(
                        trust_list_subscription::Column::DeactivatedAt,
                        Expr::value(now),
                    )
                    .filter(
                        trust_list_subscription::Column::TrustCollectionId
                            .eq(id)
                            .and(trust_list_subscription::Column::DeactivatedAt.is_null()),
                    )
                    .exec(&self.db)
                    .await
                    .map_err(to_update_data_layer_error)?;

                // Then soft deactivate the collection
                trust_collection::Entity::update(trust_collection::ActiveModel {
                    id: Unchanged(id),
                    deactivated_at: Set(Some(now)),
                    ..Default::default()
                })
                .exec(&self.db)
                .await
                .map_err(to_update_data_layer_error)?;
                Ok(())
            }
            .boxed())
            .await?
    }
}

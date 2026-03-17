use autometrics::autometrics;
use futures::FutureExt;
use one_core::model::trust_collection::{
    GetTrustCollectionList, TrustCollection, TrustCollectionListQuery, TrustCollectionRelations,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::trust_collection_repository::TrustCollectionRepository;
use sea_orm::prelude::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set, Unchanged,
};
use shared_types::TrustCollectionId;
use time::OffsetDateTime;

use super::TrustCollectionProvider;
use crate::common::list_query_with_base_model;
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

    async fn get(
        &self,
        id: &TrustCollectionId,
        relations: &TrustCollectionRelations,
    ) -> Result<Option<TrustCollection>, DataLayerError> {
        let trust_collection = trust_collection::Entity::find_by_id(*id)
            .filter(trust_collection::Column::DeactivatedAt.is_null())
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        let Some(trust_collection) = trust_collection else {
            return Ok(None);
        };

        let organisation_id = trust_collection.organisation_id;
        let mut result = TrustCollection::from(trust_collection);
        if let Some(organisation_relations) = &relations.organisation {
            result.organisation = Some(
                self.organisation_repository
                    .get_organisation(&organisation_id, organisation_relations)
                    .await?
                    .ok_or(DataLayerError::MissingRequiredRelation {
                        relation: "trust_collection-organisation",
                        id: organisation_id.to_string(),
                    })?,
            );
        }
        Ok(Some(result))
    }

    async fn list(
        &self,
        query: TrustCollectionListQuery,
    ) -> Result<GetTrustCollectionList, DataLayerError> {
        let db_query = trust_collection::Entity::find()
            .filter(trust_collection::Column::DeactivatedAt.is_null())
            .with_list_query(&query)
            .order_by_desc(trust_collection::Column::CreatedDate)
            .order_by_desc(trust_collection::Column::Id);

        list_query_with_base_model(db_query, query, &self.db).await
    }

    async fn delete(&self, id: TrustCollectionId) -> Result<(), DataLayerError> {
        self.db
            .tx(async {
                // First soft delete all subscriptions
                let now = OffsetDateTime::now_utc();
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

use autometrics::autometrics;
use one_core::model::history::{
    GetHistoryList, History, HistoryAction, HistoryListQuery, HistoryMetadata,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::history_repository::HistoryRepository;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
};
use shared_types::{EntityId, HistoryId};

use super::mapper::create_list_response;
use crate::entity::history;
use crate::history::HistoryProvider;
use crate::list_query_generic::{SelectWithFilterJoin, SelectWithListQuery};
use crate::mapper::to_data_layer_error;

#[autometrics]
#[async_trait::async_trait]
impl HistoryRepository for HistoryProvider {
    async fn create_history(&self, request: History) -> Result<HistoryId, DataLayerError> {
        if request.action == HistoryAction::Errored
            && !matches!(request.metadata, Some(HistoryMetadata::ErrorMetadata(_)))
        {
            tracing::warn!(
                "History entry {:?} has action \"Errored\" but no error metadata",
                request
            )
        }

        let history = history::ActiveModel::try_from(request)?
            .insert(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(history.id)
    }

    async fn delete_history_by_entity_id(&self, entity_id: EntityId) -> Result<(), DataLayerError> {
        history::Entity::delete_many()
            .filter(history::Column::EntityId.eq(entity_id))
            .exec(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;
        Ok(())
    }

    async fn get_history_list(
        &self,
        query_params: HistoryListQuery,
    ) -> Result<GetHistoryList, DataLayerError> {
        let query = history::Entity::find()
            .with_list_query(&query_params)
            .with_filter_join(&query_params)
            .order_by_desc(history::Column::CreatedDate)
            .order_by_desc(history::Column::Id);

        let limit = query_params
            .pagination
            .map(|pagination| pagination.page_size as u64);

        let items_count = query
            .to_owned()
            .count(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        let history_list: Vec<history::Model> = query
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        create_list_response(history_list, limit, items_count)
    }

    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    async fn get_history_entry(
        &self,
        history_id: HistoryId,
    ) -> Result<Option<History>, DataLayerError> {
        history::Entity::find_by_id(history_id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?
            .map(TryInto::try_into)
            .transpose()
    }
}

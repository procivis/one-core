use autometrics::autometrics;
use sea_orm::{ActiveModelTrait, EntityTrait, PaginatorTrait, QueryOrder};

use one_core::{
    model::history::{GetHistoryList, History, HistoryListQuery},
    repository::{error::DataLayerError, history_repository::HistoryRepository},
};
use shared_types::HistoryId;

use super::mapper::create_list_response;
use crate::list_query_generic::SelectWithFilterJoin;
use crate::{
    entity::history, history::HistoryProvider, list_query_generic::SelectWithListQuery,
    mapper::to_data_layer_error,
};

#[autometrics]
#[async_trait::async_trait]
impl HistoryRepository for HistoryProvider {
    async fn create_history(&self, request: History) -> Result<HistoryId, DataLayerError> {
        let history = history::ActiveModel::try_from(request)?
            .insert(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(history.id)
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

        Ok(create_list_response(history_list, limit, items_count))
    }
}

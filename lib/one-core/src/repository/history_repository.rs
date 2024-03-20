use shared_types::HistoryId;

use crate::{
    model::history::{GetHistoryList, History, HistoryListQuery},
    repository::error::DataLayerError,
};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait HistoryRepository: Send + Sync {
    async fn create_history(&self, request: History) -> Result<HistoryId, DataLayerError>;

    async fn get_history_list(
        &self,
        query: HistoryListQuery,
    ) -> Result<GetHistoryList, DataLayerError>;

    async fn get_history_entry(
        &self,
        history_id: HistoryId,
    ) -> Result<Option<History>, DataLayerError>;
}

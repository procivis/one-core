use shared_types::HistoryId;

use super::dto::HistoryResponseDTO;
use crate::model::history::HistoryListQuery;
use crate::service::error::{EntityNotFoundError, ServiceError};
use crate::service::history::dto::GetHistoryListResponseDTO;
use crate::service::history::HistoryService;

impl HistoryService {
    /// Returns history list filtered by query
    ///
    /// # Arguments
    ///
    /// * `query` - Query to filter list entities
    pub async fn get_history_list(
        &self,
        query: HistoryListQuery,
    ) -> Result<GetHistoryListResponseDTO, ServiceError> {
        self.history_repository
            .get_history_list(query)
            .await?
            .try_into()
    }

    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    pub async fn get_history_entry(
        &self,
        history_id: HistoryId,
    ) -> Result<HistoryResponseDTO, ServiceError> {
        self.history_repository
            .get_history_entry(history_id)
            .await?
            .ok_or(EntityNotFoundError::History(history_id))?
            .try_into()
    }
}

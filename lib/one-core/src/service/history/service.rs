use shared_types::HistoryId;

use crate::{
    model::history::HistoryListQuery,
    service::{
        error::{EntityNotFoundError, ServiceError},
        history::{dto::GetHistoryListResponseDTO, HistoryService},
    },
};

use super::dto::HistoryResponseDTO;

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

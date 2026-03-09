use shared_types::HistoryId;

use super::HistoryService;
use super::dto::{CreateHistoryRequestDTO, GetHistoryListResponseDTO, HistoryResponseDTO};
use super::error::HistoryServiceError;
use crate::error::ContextWithErrorCode;
use crate::model::history::{History, HistoryListQuery, HistorySource};
use crate::proto::session_provider::SessionExt;

impl HistoryService {
    /// Returns history list filtered by query
    ///
    /// # Arguments
    ///
    /// * `query` - Query to filter list entities
    pub async fn get_history_list(
        &self,
        query: HistoryListQuery,
    ) -> Result<GetHistoryListResponseDTO, HistoryServiceError> {
        let history_list = self
            .history_repository
            .get_history_list(query)
            .await
            .error_while("getting history list")?;
        Ok(history_list.into())
    }

    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    pub async fn get_history_entry(
        &self,
        history_id: HistoryId,
    ) -> Result<HistoryResponseDTO, HistoryServiceError> {
        let history = self
            .history_repository
            .get_history_entry(history_id)
            .await
            .error_while("getting history")?
            .ok_or(HistoryServiceError::NotFound(history_id))?;
        Ok(history.into())
    }

    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    pub async fn create_history(
        &self,
        request: CreateHistoryRequestDTO,
    ) -> Result<HistoryId, HistoryServiceError> {
        if request.source == HistorySource::Core {
            return Err(HistoryServiceError::InvalidSource);
        }

        let mut request: History = request.into();
        request.user = self.session_provider.session().user();

        let history = self
            .history_repository
            .create_history(request)
            .await
            .error_while("creating history")?;
        tracing::info!("Created history entry: {}", history);
        Ok(history)
    }
}

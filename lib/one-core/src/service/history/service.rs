use shared_types::HistoryId;

use super::dto::HistoryResponseDTO;
use crate::model::history::{History, HistoryListQuery, HistorySource};
use crate::proto::session_provider::SessionExt;
use crate::service::error::{BusinessLogicError, EntityNotFoundError, ServiceError};
use crate::service::history::HistoryService;
use crate::service::history::dto::{CreateHistoryRequestDTO, GetHistoryListResponseDTO};

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
        let history_list = self.history_repository.get_history_list(query).await?;
        Ok(history_list.into())
    }

    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    pub async fn get_history_entry(
        &self,
        history_id: HistoryId,
    ) -> Result<HistoryResponseDTO, ServiceError> {
        let history = self
            .history_repository
            .get_history_entry(history_id)
            .await?
            .ok_or(EntityNotFoundError::History(history_id))?;
        Ok(history.into())
    }

    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    pub async fn create_history(
        &self,
        request: CreateHistoryRequestDTO,
    ) -> Result<HistoryId, ServiceError> {
        if request.source == HistorySource::Core {
            return Err(BusinessLogicError::InvalidHistorySource.into());
        }

        let mut request: History = request.into();
        request.user = self.session_provider.session().user();

        let history = self.history_repository.create_history(request).await?;
        Ok(history)
    }
}

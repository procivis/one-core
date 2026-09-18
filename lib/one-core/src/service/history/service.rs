use shared_types::HistoryId;

use super::HistoryService;
use super::dto::{
    CreateHistoryRequestDTO, GetHistoryListResponseDTO, HistoryFilterParamsDTO, HistoryResponseDTO,
};
use super::error::HistoryServiceError;
use crate::error::ContextWithErrorCode;
use crate::model::history::{History, HistorySource, SortableHistoryColumn};
use crate::proto::session_provider::SessionExt;
use crate::service::common_dto::ListQueryDTO;
use crate::validator::throw_if_org_id_not_matching_session;

impl HistoryService {
    /// Returns history list filtered by query
    ///
    /// # Arguments
    ///
    /// * `query` - Query to filter list entities
    pub async fn get_history_list(
        &self,
        filter_params: ListQueryDTO<SortableHistoryColumn, HistoryFilterParamsDTO>,
    ) -> Result<GetHistoryListResponseDTO, HistoryServiceError> {
        let history_list = self
            .history_repository
            .get_history_list(filter_params.into())
            .await
            .and_then(|list| list.require_count())
            .error_while("getting history list")?;
        Ok(history_list.into())
    }

    /// Returns details of a history entry
    ///
    /// # Arguments
    ///
    /// * `history_id` - Id of an existing history entry
    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    pub async fn get_history_entry(
        &self,
        history_id: HistoryId,
    ) -> Result<HistoryResponseDTO, HistoryServiceError> {
        let history = self
            .history_repository
            .get_history_entry(history_id)
            .await
            .error_while("getting history")?;
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
        if let Some(organisation_id) = &request.organisation_id {
            throw_if_org_id_not_matching_session(organisation_id, &*self.session_provider)
                .error_while("validating organisation")?;
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

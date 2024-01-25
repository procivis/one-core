use crate::{
    model::history::HistoryListQuery,
    service::{
        error::ServiceError,
        history::{dto::GetHistoryListResponseDTO, HistoryService},
    },
};

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
}

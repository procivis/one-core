use shared_types::{EntityId, HistoryId, OrganisationId};
use time::OffsetDateTime;

use crate::model::history::{
    GetHistoryList, History, HistoryListQuery, OrganisationStats, SystemStats,
};
use crate::repository::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait HistoryRepository: Send + Sync {
    async fn create_history(&self, request: History) -> Result<HistoryId, DataLayerError>;

    async fn delete_history_by_entity_id(&self, entity_id: EntityId) -> Result<(), DataLayerError>;

    async fn get_history_list(
        &self,
        query: HistoryListQuery,
    ) -> Result<GetHistoryList, DataLayerError>;

    async fn get_history_entry(
        &self,
        history_id: HistoryId,
    ) -> Result<Option<History>, DataLayerError>;

    async fn organisation_stats(
        &self,
        from: Option<OffsetDateTime>,
        to: OffsetDateTime,
        organisation_id: OrganisationId,
        include_previous: bool,
    ) -> Result<OrganisationStats, DataLayerError>;

    async fn system_stats(
        &self,
        from: Option<OffsetDateTime>,
        to: OffsetDateTime,
        organisation_count: usize,
    ) -> Result<SystemStats, DataLayerError>;
}

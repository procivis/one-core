use autometrics::autometrics;
use one_core::model::history::{
    GetHistoryList, History, HistoryAction, HistoryListQuery, HistoryMetadata, OrganisationStats,
    OrganisationSummaryStats, SystemStats,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::history_repository::HistoryRepository;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, FromQueryResult, PaginatorTrait,
    QueryFilter, QueryOrder,
};
use shared_types::{EntityId, HistoryId, OrganisationId};
use time::OffsetDateTime;

use super::mapper::{create_list_response, map_to_stats};
use crate::entity::history;
use crate::entity::history::HistoryEntityType;
use crate::history::HistoryProvider;
use crate::history::model::TimeSeriesRow;
use crate::history::queries::{CountOperationsQuery, count_operations_query, org_timelines_query};
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

        let (items_count, history_list) =
            tokio::join!(query.to_owned().count(&self.db), query.all(&self.db));

        let items_count = items_count.map_err(|e| DataLayerError::Db(e.into()))?;
        let history_list = history_list.map_err(|e| DataLayerError::Db(e.into()))?;

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

    async fn organisation_stats(
        &self,
        from: OffsetDateTime,
        to: OffsetDateTime,
        organisation_id: OrganisationId,
    ) -> Result<OrganisationStats, DataLayerError> {
        let db_backend = self.db.get_database_backend();
        let issuance_count_query = count_operations_query(
            from,
            organisation_id,
            HistoryEntityType::Credential,
            &[history::HistoryAction::Issued],
        );
        let verification_count_query = count_operations_query(
            from,
            organisation_id,
            HistoryEntityType::Proof,
            &[history::HistoryAction::Accepted],
        );
        let credential_lifecycle_count_query = count_operations_query(
            from,
            organisation_id,
            HistoryEntityType::Credential,
            &[
                history::HistoryAction::Offered,
                history::HistoryAction::Issued,
                history::HistoryAction::Rejected,
                history::HistoryAction::Suspended,
                history::HistoryAction::Reactivated,
                history::HistoryAction::Revoked,
                history::HistoryAction::Errored,
            ],
        );
        let timelines_query = org_timelines_query(from, to, organisation_id, &db_backend)?;
        let (issuance_count, verification_count, credential_lifecycle_count, timelines) = tokio::join!(
            self.count(&issuance_count_query),
            self.count(&verification_count_query),
            self.count(&credential_lifecycle_count_query),
            TimeSeriesRow::find_by_statement(db_backend.build(&timelines_query)).all(&self.db)
        );
        let summary_stats = OrganisationSummaryStats {
            issuance_count: issuance_count?,
            verification_count: verification_count?,
            credential_lifecycle_operation_count: credential_lifecycle_count?,
        };
        map_to_stats(
            &timelines.map_err(|err| DataLayerError::Db(err.into()))?,
            summary_stats,
            from,
            to,
        )
    }

    async fn system_stats(
        &self,
        _from: OffsetDateTime,
        _to: OffsetDateTime,
        _organisation_count: usize,
    ) -> Result<SystemStats, DataLayerError> {
        todo!()
    }
}

impl HistoryProvider {
    async fn count(&self, stmt: &CountOperationsQuery) -> Result<usize, DataLayerError> {
        let result = self
            .db
            .query_one(self.db.get_database_backend().build(&stmt.0))
            .await
            .map_err(|err| DataLayerError::Db(err.into()))?
            .ok_or(DataLayerError::MappingError)?;
        Ok(result
            .try_get::<u32>("", "count")
            .map_err(|err| DataLayerError::Db(err.into()))? as usize)
    }
}

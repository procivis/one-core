use autometrics::autometrics;
use futures::future::try_join_all;
use one_core::model::history::{
    GetHistoryList, History, HistoryAction, HistoryListQuery, HistoryMetadata, OrganisationStats,
    OrganisationSummaryStats, SystemOperationsCount, SystemStats,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::history_repository::HistoryRepository;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, FromQueryResult, PaginatorTrait,
    QueryFilter, QueryOrder,
};
use shared_types::{EntityId, HistoryId, OrganisationId};
use time::OffsetDateTime;

use super::mapper::{create_list_response, map_to_stats, to_ops_org_count};
use crate::entity::history;
use crate::entity::history::HistoryEntityType;
use crate::history::HistoryProvider;
use crate::history::model::{OrganisationOpsCount, TimeSeriesRow};
use crate::history::queries::{
    CountOperationsQuery, count_ops_query, org_timelines_query, top_orgs_query,
};
use crate::list_query_generic::{SelectWithFilterJoin, SelectWithListQuery};
use crate::mapper::to_data_layer_error;

const CREDENTIAL_LIFECYCLE_OPS: [history::HistoryAction; 7] = [
    history::HistoryAction::Offered,
    history::HistoryAction::Issued,
    history::HistoryAction::Rejected,
    history::HistoryAction::Suspended,
    history::HistoryAction::Reactivated,
    history::HistoryAction::Revoked,
    history::HistoryAction::Errored,
];

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
        let issuance_count_query = count_ops_query(
            HistoryEntityType::Credential,
            &[history::HistoryAction::Issued],
            None,
            from,
            Some(organisation_id),
        );
        let verification_count_query = count_ops_query(
            HistoryEntityType::Proof,
            &[history::HistoryAction::Accepted],
            None,
            from,
            Some(organisation_id),
        );
        let credential_lifecycle_count_query = count_ops_query(
            HistoryEntityType::Credential,
            &CREDENTIAL_LIFECYCLE_OPS,
            None,
            from,
            Some(organisation_id),
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
        from: OffsetDateTime,
        to: OffsetDateTime,
        organisation_count: usize,
    ) -> Result<SystemStats, DataLayerError> {
        let db_backend = self.db.get_database_backend();
        let top_issuers = top_orgs_query(
            HistoryEntityType::Credential,
            history::HistoryAction::Issued,
            to,
            organisation_count,
        );
        let top_verifiers = top_orgs_query(
            HistoryEntityType::Proof,
            history::HistoryAction::Accepted,
            to,
            organisation_count,
        );
        let (top_issuers, top_verifiers, (system_stats_from, system_stats_to)) = tokio::try_join!(
            async {
                OrganisationOpsCount::find_by_statement(db_backend.build(&top_issuers))
                    .all(&self.db)
                    .await
                    .map_err(|err| DataLayerError::Db(err.into()))
            },
            async {
                OrganisationOpsCount::find_by_statement(db_backend.build(&top_verifiers))
                    .all(&self.db)
                    .await
                    .map_err(|err| DataLayerError::Db(err.into()))
            },
            self.system_operations_counts(from, to)
        )?;
        let mut top_iss_diffs = vec![];
        for issuer in &top_issuers {
            let count = async move {
                let query = count_ops_query(
                    HistoryEntityType::Credential,
                    &[history::HistoryAction::Issued],
                    Some(from),
                    to,
                    Some(issuer.organisation_id),
                );
                self.count(&query).await
            };
            top_iss_diffs.push(count);
        }
        let mut top_verifier_diffs = vec![];
        for verifier in &top_verifiers {
            let count = async move {
                let query = count_ops_query(
                    HistoryEntityType::Proof,
                    &[history::HistoryAction::Accepted],
                    Some(from),
                    to,
                    Some(verifier.organisation_id),
                );
                self.count(&query).await
            };
            top_verifier_diffs.push(count);
        }

        let (diffs_issuers, diffs_verifiers) = tokio::try_join!(
            try_join_all(top_iss_diffs),
            try_join_all(top_verifier_diffs)
        )?;

        Ok(SystemStats {
            from: system_stats_from,
            to: system_stats_to,
            top_issuers: to_ops_org_count(&top_issuers, &diffs_issuers)?,
            top_verifiers: to_ops_org_count(&top_verifiers, &diffs_verifiers)?,
        })
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

    async fn system_operations_counts(
        &self,
        from: OffsetDateTime,
        to: OffsetDateTime,
    ) -> Result<(SystemOperationsCount, SystemOperationsCount), DataLayerError> {
        use HistoryEntityType::*;
        use history::HistoryAction::*;
        let issuances = self.system_ops_count_from_to(Credential, &[Issued], from, to);
        let verifications = self.system_ops_count_from_to(Proof, &[Accepted], from, to);
        let cred_lifecyle_ops =
            self.system_ops_count_from_to(Credential, &CREDENTIAL_LIFECYCLE_OPS, from, to);
        let sessions = self.system_ops_count_from_to(StsSession, &[Created], from, to);
        let wallet_units_new =
            self.system_ops_count_from_to(WalletUnit, &[Created, Activated], from, to);
        let wallet_units_revoked = self.system_ops_count_from_to(WalletUnit, &[Revoked], from, to);
        let (
            (issuances_from, issuances_to),
            (verifications_from, verifications_to),
            (cred_lifecyle_ops_from, cred_lifecyle_ops_to),
            (sessions_from, sessions_to),
            (wallet_units_new_from, wallet_units_new_to),
            (wallet_units_revoked_from, wallet_units_revoked_to),
        ) = tokio::try_join!(
            issuances,
            verifications,
            cred_lifecyle_ops,
            sessions,
            wallet_units_new,
            wallet_units_revoked
        )?;
        let from_stats = SystemOperationsCount {
            issuance_count: issuances_from,
            verification_count: verifications_from,
            credential_lifecycle_operation_count: cred_lifecyle_ops_from,
            session_token_count: sessions_from,
            active_wallet_unit_count: wallet_units_new_from - wallet_units_revoked_from,
        };
        let to_stats = SystemOperationsCount {
            issuance_count: issuances_to,
            verification_count: verifications_to,
            credential_lifecycle_operation_count: cred_lifecyle_ops_to,
            session_token_count: sessions_to,
            active_wallet_unit_count: wallet_units_new_to - wallet_units_revoked_to,
        };
        Ok((from_stats, to_stats))
    }

    async fn system_ops_count_from_to(
        &self,
        entity_type: HistoryEntityType,
        actions: &[history::HistoryAction],
        from: OffsetDateTime,
        to: OffsetDateTime,
    ) -> Result<(usize, usize), DataLayerError> {
        let from_query = count_ops_query(entity_type, actions, None, from, None);
        let diff_query = count_ops_query(entity_type, actions, Some(from), to, None);
        let (from_count, diff) = tokio::join!(self.count(&from_query), self.count(&diff_query));
        let from_count = from_count?;
        let to_count = from_count + diff?;
        Ok((from_count, to_count))
    }
}

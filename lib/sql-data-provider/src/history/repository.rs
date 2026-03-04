use autometrics::autometrics;
use futures::future::try_join_all;
use one_core::model::history::{
    GetHistoryList, GetIssuerStats, GetVerifierStats, History, HistoryAction, HistoryListQuery,
    HistoryMetadata, IssuerStatsQuery, OrganisationStats, OrganisationSummaryStats,
    SystemOperationsCount, SystemStats, VerifierStatsQuery,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::history_repository::HistoryRepository;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, FromQueryResult, PaginatorTrait,
    QueryFilter, QueryOrder,
};
use shared_types::{EntityId, HistoryId, OrganisationId};
use time::OffsetDateTime;

use super::mapper::{
    create_list_response, map_to_issuer_stats, map_to_stats, map_to_verifier_stats,
    to_ops_org_count,
};
use crate::entity::history;
use crate::entity::history::HistoryEntityType;
use crate::history::HistoryProvider;
use crate::history::model::{
    IssuerStatsRow, OrganisationOpsCount, TimeSeriesRow, VerifierStatsRow, WindowCount,
};
use crate::history::queries::{
    CountOperationsQuery, count_ops_query, issuer_stats_query, org_timelines_query, top_orgs_query,
    verifier_stats_query,
};
use crate::list_query_generic::{SelectWithFilterJoin, SelectWithListQuery};
use crate::mapper::to_data_layer_error;

const CREDENTIAL_LIFECYCLE_OPS: [history::HistoryAction; 3] = [
    history::HistoryAction::Suspended,
    history::HistoryAction::Reactivated,
    history::HistoryAction::Revoked,
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
        from: Option<OffsetDateTime>,
        to: OffsetDateTime,
        organisation_id: OrganisationId,
        include_previous: bool,
    ) -> Result<OrganisationStats, DataLayerError> {
        let db_backend = self.db.get_database_backend();
        let issuance_count_query = self.window_counts(
            HistoryEntityType::Credential,
            &[history::HistoryAction::Issued],
            from,
            to,
            Some(organisation_id),
            include_previous,
        );
        let verification_count_query = self.window_counts(
            HistoryEntityType::Proof,
            &[history::HistoryAction::Accepted],
            from,
            to,
            Some(organisation_id),
            include_previous,
        );
        let credential_lifecycle_count_query = self.window_counts(
            HistoryEntityType::Credential,
            &CREDENTIAL_LIFECYCLE_OPS,
            from,
            to,
            Some(organisation_id),
            include_previous,
        );
        let timelines_query = org_timelines_query(from, to, organisation_id, &db_backend)?;
        let (issuance_count, verification_count, credential_lifecycle_count, timelines) = tokio::try_join!(
            issuance_count_query,
            verification_count_query,
            credential_lifecycle_count_query,
            async {
                TimeSeriesRow::find_by_statement(db_backend.build(&timelines_query))
                    .all(&self.db)
                    .await
                    .map_err(|err| DataLayerError::Db(err.into()))
            }
        )?;
        let timelines = map_to_stats(&timelines, from, to)?;
        let previous = match (
            issuance_count.previous,
            verification_count.previous,
            credential_lifecycle_count.previous,
        ) {
            (
                Some(issuance_count),
                Some(verification_count),
                Some(credential_lifecycle_operation_count),
            ) => Some(OrganisationSummaryStats {
                issuance_count,
                verification_count,
                credential_lifecycle_operation_count,
            }),
            (None, None, None) => None,
            _ => Err(DataLayerError::MappingError)?,
        };
        Ok(OrganisationStats {
            previous,
            current: OrganisationSummaryStats {
                issuance_count: issuance_count.current,
                verification_count: verification_count.current,
                credential_lifecycle_operation_count: credential_lifecycle_count.current,
            },
            timelines,
        })
    }

    async fn system_stats(
        &self,
        from: Option<OffsetDateTime>,
        to: OffsetDateTime,
        organisation_count: usize,
    ) -> Result<SystemStats, DataLayerError> {
        let db_backend = self.db.get_database_backend();
        let top_issuers = top_orgs_query(
            HistoryEntityType::Credential,
            history::HistoryAction::Issued,
            from,
            to,
            organisation_count,
        );
        let top_verifiers = top_orgs_query(
            HistoryEntityType::Proof,
            history::HistoryAction::Accepted,
            from,
            to,
            organisation_count,
        );
        let (top_issuers, top_verifiers, (system_stats_current, system_stats_previous)) = tokio::try_join!(
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

        let Some(from) = from else {
            return Ok(SystemStats {
                current: system_stats_current,
                previous: system_stats_previous,
                top_issuers: to_ops_org_count(&top_issuers, None)?,
                top_verifiers: to_ops_org_count(&top_verifiers, None)?,
            });
        };
        let window_size = to - from;
        let prev_window_start = from - window_size;
        let mut top_iss_prev = vec![];
        let mut top_verifier_prev = vec![];
        for issuer in &top_issuers {
            let count = async move {
                let query = count_ops_query(
                    HistoryEntityType::Credential,
                    &[history::HistoryAction::Issued],
                    Some(prev_window_start),
                    from,
                    Some(issuer.organisation_id),
                );
                self.count(&query).await
            };
            top_iss_prev.push(count);
        }
        for verifier in &top_verifiers {
            let count = async move {
                let query = count_ops_query(
                    HistoryEntityType::Proof,
                    &[history::HistoryAction::Accepted],
                    Some(prev_window_start),
                    from,
                    Some(verifier.organisation_id),
                );
                self.count(&query).await
            };
            top_verifier_prev.push(count);
        }

        let (prev_issuers, prev_verifiers) =
            tokio::try_join!(try_join_all(top_iss_prev), try_join_all(top_verifier_prev))?;
        Ok(SystemStats {
            current: system_stats_current,
            previous: system_stats_previous,
            top_issuers: to_ops_org_count(&top_issuers, Some(&prev_issuers))?,
            top_verifiers: to_ops_org_count(&top_verifiers, Some(&prev_verifiers))?,
        })
    }

    async fn issuer_stats(
        &self,
        current_query: IssuerStatsQuery,
        previous_query: Option<IssuerStatsQuery>,
    ) -> Result<GetIssuerStats, DataLayerError> {
        let limit = current_query
            .pagination
            .as_ref()
            .map(|pagination| pagination.page_size as u64);
        let backend = self.db.get_database_backend();
        let query = issuer_stats_query(&current_query);
        let current = backend.build(&query);
        let prev = previous_query.map(|q| backend.build(&issuer_stats_query(&q)));
        let (current, count, prev) = tokio::join!(
            IssuerStatsRow::find_by_statement(current.clone()).all(&self.db),
            IssuerStatsRow::find_by_statement(current).count(&self.db),
            async {
                let result = IssuerStatsRow::find_by_statement(prev?)
                    .all(&self.db)
                    .await
                    .map_err(|err| DataLayerError::Db(err.into()));
                Some(result)
            }
        );
        let current = current.map_err(|err| DataLayerError::Db(err.into()))?;
        let count = count.map_err(|err| DataLayerError::Db(err.into()))?;
        let prev = prev
            .transpose()
            .map_err(|err| DataLayerError::Db(err.into()))?;
        let stats = map_to_issuer_stats(current, prev, count, limit);
        Ok(stats)
    }

    async fn verifier_stats(
        &self,
        current_query: VerifierStatsQuery,
        previous_query: Option<VerifierStatsQuery>,
    ) -> Result<GetVerifierStats, DataLayerError> {
        let limit = current_query
            .pagination
            .as_ref()
            .map(|pagination| pagination.page_size as u64);
        let backend = self.db.get_database_backend();
        let query = verifier_stats_query(&current_query);
        let current = backend.build(&query);
        let prev = previous_query.map(|q| backend.build(&verifier_stats_query(&q)));
        let (current, count, prev) = tokio::join!(
            VerifierStatsRow::find_by_statement(current.clone()).all(&self.db),
            VerifierStatsRow::find_by_statement(current).count(&self.db),
            async {
                let result = VerifierStatsRow::find_by_statement(prev?)
                    .all(&self.db)
                    .await
                    .map_err(|err| DataLayerError::Db(err.into()));
                Some(result)
            }
        );
        let current = current.map_err(|err| DataLayerError::Db(err.into()))?;
        let count = count.map_err(|err| DataLayerError::Db(err.into()))?;
        let prev = prev
            .transpose()
            .map_err(|err| DataLayerError::Db(err.into()))?;
        let stats = map_to_verifier_stats(current, prev, count, limit);
        Ok(stats)
    }
}

impl HistoryProvider {
    async fn count(&self, stmt: &CountOperationsQuery) -> Result<usize, DataLayerError> {
        let statement = self.db.get_database_backend().build(&stmt.0);
        let result = self
            .db
            .query_one(statement)
            .await
            .map_err(|err| DataLayerError::Db(err.into()))?
            .ok_or(DataLayerError::MappingError)?;
        Ok(result
            .try_get::<i64>("", "count")
            .map_err(|err| DataLayerError::Db(err.into()))? as usize)
    }

    async fn system_operations_counts(
        &self,
        from: Option<OffsetDateTime>,
        to: OffsetDateTime,
    ) -> Result<(SystemOperationsCount, Option<SystemOperationsCount>), DataLayerError> {
        use HistoryEntityType::*;
        use history::HistoryAction::*;
        let issuances = self.window_counts(Credential, &[Issued], from, to, None, true);
        let verifications = self.window_counts(Proof, &[Accepted], from, to, None, true);
        let credential_lifecycle =
            self.window_counts(Credential, &CREDENTIAL_LIFECYCLE_OPS, from, to, None, true);
        let sessions = self.window_counts(StsSession, &[Created], from, to, None, true);
        let wallet_units_new =
            self.window_counts(WalletUnit, &[Created, Activated], from, to, None, true);
        let wallet_units_revoked = self.window_counts(WalletUnit, &[Revoked], from, to, None, true);
        let (
            issuance_count,
            verification_count,
            credential_lifecycle_count,
            session_count,
            wallet_unit_new_count,
            wallet_unit_revoked_count,
        ) = tokio::try_join!(
            issuances,
            verifications,
            credential_lifecycle,
            sessions,
            wallet_units_new,
            wallet_units_revoked
        )?;

        let current = SystemOperationsCount {
            issuance_count: issuance_count.current,
            verification_count: verification_count.current,
            credential_lifecycle_operation_count: credential_lifecycle_count.current,
            session_token_count: session_count.current,
            active_wallet_unit_count: wallet_unit_new_count.current
                - wallet_unit_revoked_count.current,
        };

        let previous = match (
            issuance_count.previous,
            verification_count.previous,
            credential_lifecycle_count.previous,
            session_count.previous,
            wallet_unit_new_count.previous,
            wallet_unit_revoked_count.previous,
        ) {
            (
                Some(issuance_count),
                Some(verification_count),
                Some(credential_lifecycle_operation_count),
                Some(session_token_count),
                Some(wallet_unit_new_count),
                Some(wallet_unit_revoked_count),
            ) => Some(SystemOperationsCount {
                issuance_count,
                verification_count,
                credential_lifecycle_operation_count,
                session_token_count,
                active_wallet_unit_count: wallet_unit_new_count - wallet_unit_revoked_count,
            }),
            (None, None, None, None, None, None) => None,
            _ => Err(DataLayerError::MappingError)?,
        };

        Ok((current, previous))
    }

    async fn window_counts(
        &self,
        entity_type: HistoryEntityType,
        actions: &[history::HistoryAction],
        from: Option<OffsetDateTime>,
        to: OffsetDateTime,
        organisation_id: Option<OrganisationId>,
        include_previous: bool,
    ) -> Result<WindowCount, DataLayerError> {
        let current_query = count_ops_query(entity_type, actions, from, to, organisation_id);
        if !include_previous {
            return Ok(WindowCount {
                current: self.count(&current_query).await?,
                previous: None,
            });
        }
        let Some(from) = from else {
            return Ok(WindowCount {
                current: self.count(&current_query).await?,
                previous: None,
            });
        };
        let window_size = to - from;
        let prev_window_start = from - window_size;
        let prev_query = count_ops_query(
            entity_type,
            actions,
            Some(prev_window_start),
            from,
            organisation_id,
        );
        let (current, prev) =
            tokio::try_join!(self.count(&current_query), self.count(&prev_query))?;
        Ok(WindowCount {
            current,
            previous: Some(prev),
        })
    }
}

use one_dto_mapper::convert_inner;
use shared_types::OrganisationId;

use crate::error::ContextWithErrorCode;
use crate::model::common::SortDirection;
use crate::model::history::IssuerStatsQuery;
use crate::model::list_query::{ListPagination, ListSorting};
use crate::model::organisation::OrganisationListQuery;
use crate::model::organisation::SortableOrganisationColumn::CreatedDate;
use crate::service::error::EntityNotFoundError;
use crate::service::statistics::StatisticsService;
use crate::service::statistics::dto::{
    GetIssuerStatsResponseDTO, NewOrganisationEntryDTO, OrganisationStatsRequestDTO,
    OrganisationStatsResponseDTO, SystemStatsRequestDTO, SystemStatsResponseDTO,
};
use crate::service::statistics::error::StatisticsError;
use crate::validator::throw_if_org_not_matching_session;

impl StatisticsService {
    pub async fn organisation_stats(
        &self,
        request: OrganisationStatsRequestDTO,
    ) -> Result<OrganisationStatsResponseDTO, StatisticsError> {
        throw_if_org_not_matching_session(&request.organisation_id, &*self.session_provider)
            .error_while("validating organisation")?;
        let (from, include_previous) = match request.from {
            Some(from) => (from, true),
            None => {
                let organisation = self
                    .organisation_repository
                    .get_organisation(&request.organisation_id, &Default::default())
                    .await
                    .error_while("getting organisation")?
                    .ok_or(EntityNotFoundError::Organisation(request.organisation_id))
                    .error_while("getting organisation")?;
                (organisation.created_date, false)
            }
        };

        let result = self
            .history_repository
            .organisation_stats(
                Some(from),
                request.to,
                request.organisation_id,
                include_previous,
            )
            .await
            .error_while("getting organisation statistics")?;
        Ok(result.into())
    }

    pub async fn system_stats(
        &self,
        request: SystemStatsRequestDTO,
    ) -> Result<SystemStatsResponseDTO, StatisticsError> {
        // No session org check because this is a cross-org call
        let (newest_orgs, stats) = tokio::join!(
            self.organisation_repository
                .get_organisation_list(OrganisationListQuery {
                    pagination: Some(ListPagination {
                        page: 0,
                        page_size: request.organisation_count as u32,
                    }),
                    sorting: Some(ListSorting {
                        column: CreatedDate,
                        direction: Some(SortDirection::Descending),
                    }),
                    ..Default::default()
                }),
            self.history_repository.system_stats(
                request.from,
                request.to,
                request.organisation_count
            )
        );
        let newest_orgs = newest_orgs.error_while("getting newest organisations")?;
        let stats = stats.error_while("getting system statistics")?;
        Ok(SystemStatsResponseDTO {
            previous: convert_inner(stats.previous),
            current: stats.current.into(),
            top_issuers: convert_inner(stats.top_issuers),
            top_verifiers: convert_inner(stats.top_verifiers),
            newest_organisations: newest_orgs
                .values
                .iter()
                .map(|o| NewOrganisationEntryDTO {
                    organisation: o.id,
                    created_date: o.created_date,
                })
                .collect(),
        })
    }

    pub async fn issuer_stats(
        &self,
        organisation_id: &OrganisationId,
        current: IssuerStatsQuery,
        previous: Option<IssuerStatsQuery>,
    ) -> Result<GetIssuerStatsResponseDTO, StatisticsError> {
        throw_if_org_not_matching_session(organisation_id, &*self.session_provider)
            .error_while("validating organisation")?;
        let stats = self
            .history_repository
            .issuer_stats(current, previous)
            .await
            .error_while("getting issuer statistics")?;
        Ok(stats.into())
    }
}

use one_core::model::history::{
    IssuerStatsQuery, StatsBySchemaFilterValue, SystemInteractionStatsQuery,
    SystemStatsFilterValue, VerifierStatsQuery,
};
use one_core::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, ValueComparison,
};
use one_core::service::error::ServiceError;
use one_core::service::statistics::dto::SystemStatsRequestDTO;
use one_dto_mapper::try_convert_inner;
use time::OffsetDateTime;

use crate::dto::common::SortDirection;
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::endpoint::statistics::dto::{
    GetIssuerSchemaStatsQueryRest, GetSystemInteractionStatsQueryRest,
    GetVerifierSchemaStatsQueryRest, SortableIssuerStatisticsColumnRestDTO,
    SortableSystemInteractionStatisticsColumnRestDTO, SortableVerifierStatisticsColumnRestDTO,
    StatsBySchemaFilterParamsRest, SystemStatsFilterParamsRest, SystemStatsRequestQuery,
};

impl From<SystemStatsRequestQuery> for SystemStatsRequestDTO {
    fn from(value: SystemStatsRequestQuery) -> Self {
        Self {
            from: value.from,
            to: value.to,
            organisation_count: value.organisation_count.unwrap_or(5),
        }
    }
}

pub(super) fn map_to_issuer_stats_queries(
    mut query: GetIssuerSchemaStatsQueryRest,
) -> Result<(IssuerStatsQuery, Option<IssuerStatsQuery>), ServiceError> {
    // Default sort
    if query.sort.is_none() {
        query.sort = Some(SortableIssuerStatisticsColumnRestDTO::Issued)
    }
    if query.sort_direction.is_none() {
        query.sort_direction = Some(SortDirection::Descending);
    }
    let current = query.clone().try_into()?;
    let prev_boundaries =
        shift_time_boundaries(query.filter.from, query.filter.to)?.map(|(from, to)| {
            query.filter.to = to;
            query.filter.from = Some(from);
            query
        });
    let prev = try_convert_inner(prev_boundaries)?;
    Ok((current, prev))
}

pub(super) fn map_to_verifier_stats_queries(
    mut query: GetVerifierSchemaStatsQueryRest,
) -> Result<(VerifierStatsQuery, Option<VerifierStatsQuery>), ServiceError> {
    // Default sort
    if query.sort.is_none() {
        query.sort = Some(SortableVerifierStatisticsColumnRestDTO::Accepted)
    }
    if query.sort_direction.is_none() {
        query.sort_direction = Some(SortDirection::Descending);
    }
    let current = query.clone().try_into()?;
    let prev_boundaries =
        shift_time_boundaries(query.filter.from, query.filter.to)?.map(|(from, to)| {
            query.filter.to = to;
            query.filter.from = Some(from);
            query
        });
    let prev = try_convert_inner(prev_boundaries)?;
    Ok((current, prev))
}

pub(super) fn map_to_system_interaction_stats_queries(
    mut query: GetSystemInteractionStatsQueryRest,
) -> Result<
    (
        SystemInteractionStatsQuery,
        Option<SystemInteractionStatsQuery>,
    ),
    ServiceError,
> {
    // Default sort
    if query.sort.is_none() {
        query.sort = Some(SortableSystemInteractionStatisticsColumnRestDTO::Issued)
    }
    if query.sort_direction.is_none() {
        query.sort_direction = Some(SortDirection::Descending);
    }
    let current = query.clone().try_into()?;
    let prev_boundaries =
        shift_time_boundaries(query.filter.from, query.filter.to)?.map(|(from, to)| {
            query.filter.to = to;
            query.filter.from = Some(from);
            query
        });
    let prev = try_convert_inner(prev_boundaries)?;
    Ok((current, prev))
}

fn shift_time_boundaries(
    from: Option<OffsetDateTime>,
    to: OffsetDateTime,
) -> Result<Option<(OffsetDateTime, OffsetDateTime)>, ServiceError> {
    let Some(from) = from else {
        return Ok(None);
    };
    // shift time filters for the previous window query
    let diff = to - from;
    if diff.is_negative() {
        return Err(ServiceError::ValidationError(
            "`from` timestamp must not be after `to` timestamp".to_string(),
        ));
    }
    Ok(Some((from - diff, from)))
}

impl TryFrom<StatsBySchemaFilterParamsRest> for ListFilterCondition<StatsBySchemaFilterValue> {
    type Error = ServiceError;

    fn try_from(value: StatsBySchemaFilterParamsRest) -> Result<Self, Self::Error> {
        let organisation_id = StatsBySchemaFilterValue::OrganisationId(
            fallback_organisation_id_from_session(value.organisation_id)?,
        )
        .condition();

        let to = StatsBySchemaFilterValue::From(ValueComparison {
            comparison: ComparisonType::LessThan,
            value: value.to,
        })
        .condition();

        let from = value.from.map(|t| {
            StatsBySchemaFilterValue::From(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: t,
            })
        });

        Ok(organisation_id & to & from)
    }
}

impl TryFrom<SystemStatsFilterParamsRest> for ListFilterCondition<SystemStatsFilterValue> {
    type Error = ServiceError;
    fn try_from(value: SystemStatsFilterParamsRest) -> Result<Self, Self::Error> {
        let to = SystemStatsFilterValue::From(ValueComparison {
            comparison: ComparisonType::LessThan,
            value: value.to,
        })
        .condition();

        let from = value.from.map(|t| {
            SystemStatsFilterValue::From(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: t,
            })
        });

        Ok(to & from)
    }
}

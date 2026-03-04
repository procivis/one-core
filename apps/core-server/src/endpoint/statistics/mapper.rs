use one_core::model::history::{IssuerStatsQuery, StatsBySchemaFilterValue};
use one_core::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, ValueComparison,
};
use one_core::service::error::ServiceError;
use one_core::service::statistics::dto::SystemStatsRequestDTO;

use crate::dto::common::SortDirection;
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::endpoint::statistics::dto::{
    GetSchemaStatsQueryRest, SortableIssuerStatisticsColumnRestDTO, StatsBySchemaFilterParamsRest,
    SystemStatsRequestQuery,
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

pub(super) fn map_to_current_and_prev(
    mut query: GetSchemaStatsQueryRest,
) -> Result<(IssuerStatsQuery, Option<IssuerStatsQuery>), ServiceError> {
    // Default sort
    if query.sort.is_none() {
        query.sort = Some(SortableIssuerStatisticsColumnRestDTO::Issued)
    }
    if query.sort_direction.is_none() {
        query.sort_direction = Some(SortDirection::Descending);
    }

    let current = query.clone().try_into()?;
    let prev = if let Some(from) = query.filter.from {
        // shift time filters for the previous window query
        let diff = query.filter.to - from;
        if diff.is_negative() {
            return Err(ServiceError::ValidationError(
                "`from` timestamp must not be after `to` timestamp".to_string(),
            ));
        }
        let mut prev_query = query;
        prev_query.filter.from = Some(from - diff);
        prev_query.filter.to = from;
        Some(prev_query.try_into()?)
    } else {
        None
    };
    Ok((current, prev))
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

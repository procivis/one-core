use one_core::model::history::{
    GetHistoryList, History, IssuerTimelines, OrganisationStats, OrganisationSummaryStats,
    OrganisationTimelines, TimeSeriesPoint, VerifierTimelines,
};
use one_core::repository::error::DataLayerError;
use one_dto_mapper::try_convert_inner;
use sea_orm::ActiveValue::Set;
use time::{Duration, Month, OffsetDateTime};

use crate::common::calculate_pages_count;
use crate::entity::history;
use crate::entity::history::{HistoryAction, HistoryEntityType};
use crate::history::model::{TimeResolution, TimeSeriesRow};

impl TryFrom<history::Model> for History {
    type Error = DataLayerError;

    fn try_from(value: history::Model) -> Result<Self, Self::Error> {
        let metadata = value
            .metadata
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|_| Self::Error::MappingError)?;

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            action: value.action.into(),
            entity_id: value.entity_id,
            entity_type: value.entity_type.into(),
            metadata,
            organisation_id: value.organisation_id,
            name: value.name,
            source: value.source.into(),
            target: value.target,
            user: value.user,
        })
    }
}

impl TryFrom<History> for history::ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: History) -> Result<Self, Self::Error> {
        let metadata = value
            .metadata
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| Self::Error::MappingError)?;

        Ok(Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            action: Set(value.action.into()),
            entity_id: Set(value.entity_id),
            entity_type: Set(value.entity_type.into()),
            metadata: Set(metadata),
            organisation_id: Set(value.organisation_id),
            name: Set(value.name),
            source: Set(value.source.into()),
            target: Set(value.target),
            user: Set(value.user),
        })
    }
}

pub(super) fn create_list_response(
    history_list: Vec<history::Model>,
    limit: Option<u64>,
    items_count: u64,
) -> Result<GetHistoryList, DataLayerError> {
    Ok(GetHistoryList {
        values: try_convert_inner(history_list)?,
        total_pages: calculate_pages_count(items_count, limit.unwrap_or(0)),
        total_items: items_count,
    })
}

pub(super) fn map_to_stats(
    rows: &[TimeSeriesRow],
    from_summary_stats: OrganisationSummaryStats,
    from: OffsetDateTime,
    to: OffsetDateTime,
) -> Result<OrganisationStats, DataLayerError> {
    let resolution = TimeResolution::new(from, to);
    // Align timestamps to start of their respective bucket boundary
    let from = floor(from, resolution)?;
    let to = floor(to, resolution)?;

    let mut result = OrganisationStats {
        from: from_summary_stats.clone(),
        // to counts will be increased as the code iterates over the time series
        to: from_summary_stats,
        timelines: OrganisationTimelines {
            issuer: IssuerTimelines {
                offered: vec![],
                issued: vec![],
                rejected: vec![],
                suspended: vec![],
                reactivated: vec![],
                revoked: vec![],
                error: vec![],
            },
            verifier: VerifierTimelines {
                pending: vec![],
                accepted: vec![],
                rejected: vec![],
                error: vec![],
            },
        },
    };

    let Some(first) = rows.first() else {
        // Empty rows, create zero time series
        fill_missing_zeros(&mut result, resolution, from, to, FillMode::Inclusive)?;
        return Ok(result);
    };

    // Fill in zeros up to the first timestamp
    fill_missing_zeros(
        &mut result,
        resolution,
        from,
        first.timestamp,
        FillMode::Exclusive,
    )?;

    let mut prev_timestamp = None;
    for row in rows {
        if let Some(prev_ts) = prev_timestamp
            && prev_ts != row.timestamp
        {
            prev_timestamp = Some(row.timestamp);
            // Immediately fill gaps, if any
            fill_missing_zeros(
                &mut result,
                resolution,
                prev_ts,
                row.timestamp,
                FillMode::Exclusive,
            )?;
        }
        let count = row.count as usize;
        let point = TimeSeriesPoint {
            timestamp: row.timestamp,
            count,
        };
        match row.entity_type {
            HistoryEntityType::Credential => {
                result.to.credential_lifecycle_operation_count += count;
                match row.action {
                    HistoryAction::Offered => result.timelines.issuer.offered.push(point),
                    HistoryAction::Issued => {
                        result.to.issuance_count += count;
                        result.timelines.issuer.issued.push(point)
                    }
                    HistoryAction::Rejected => result.timelines.issuer.rejected.push(point),
                    HistoryAction::Suspended => result.timelines.issuer.suspended.push(point),
                    HistoryAction::Reactivated => result.timelines.issuer.reactivated.push(point),
                    HistoryAction::Revoked => result.timelines.issuer.revoked.push(point),
                    HistoryAction::Errored => result.timelines.issuer.error.push(point),
                    _ => return Err(DataLayerError::MappingError),
                }
            }
            HistoryEntityType::Proof => match row.action {
                HistoryAction::Pending => result.timelines.verifier.pending.push(point),
                HistoryAction::Accepted => {
                    result.to.verification_count += count;
                    result.timelines.verifier.accepted.push(point)
                }
                HistoryAction::Rejected => result.timelines.verifier.rejected.push(point),
                HistoryAction::Errored => result.timelines.verifier.error.push(point),
                _ => return Err(DataLayerError::MappingError),
            },
            _ => return Err(DataLayerError::MappingError),
        }
    }
    // make sure the end is covered in all time series
    fill_missing_zeros(&mut result, resolution, from, to, FillMode::Inclusive)?;
    Ok(result)
}

#[derive(Debug, Copy, Clone)]
enum FillMode {
    Inclusive,
    Exclusive,
}

fn fill_missing_zeros(
    stats: &mut OrganisationStats,
    resolution: TimeResolution,
    from: OffsetDateTime,
    to: OffsetDateTime,
    mode: FillMode,
) -> Result<(), DataLayerError> {
    let issuer = &mut stats.timelines.issuer;
    fill_zeros(&mut issuer.offered, resolution, from, to, mode)?;
    fill_zeros(&mut issuer.issued, resolution, from, to, mode)?;
    fill_zeros(&mut issuer.rejected, resolution, from, to, mode)?;
    fill_zeros(&mut issuer.suspended, resolution, from, to, mode)?;
    fill_zeros(&mut issuer.reactivated, resolution, from, to, mode)?;
    fill_zeros(&mut issuer.revoked, resolution, from, to, mode)?;
    fill_zeros(&mut issuer.error, resolution, from, to, mode)?;
    let verifier = &mut stats.timelines.verifier;
    fill_zeros(&mut verifier.pending, resolution, from, to, mode)?;
    fill_zeros(&mut verifier.accepted, resolution, from, to, mode)?;
    fill_zeros(&mut verifier.rejected, resolution, from, to, mode)?;
    fill_zeros(&mut verifier.error, resolution, from, to, mode)
}

fn fill_zeros(
    stats: &mut Vec<TimeSeriesPoint>,
    time_resolution: TimeResolution,
    from: OffsetDateTime,
    to: OffsetDateTime,
    mode: FillMode,
) -> Result<(), DataLayerError> {
    let from = if let Some(last_point) = stats.last() {
        last_point.timestamp
    } else {
        stats.push(zero_point(from));
        from
    };
    let mut next_ts = next_timestamp(from, time_resolution)?;
    while match mode {
        FillMode::Inclusive => next_ts <= to,
        FillMode::Exclusive => next_ts < to,
    } {
        stats.push(zero_point(next_ts));
        next_ts = next_timestamp(next_ts, time_resolution)?;
    }
    Ok(())
}

fn next_timestamp(
    current: OffsetDateTime,
    resolution: TimeResolution,
) -> Result<OffsetDateTime, DataLayerError> {
    let new = match resolution {
        TimeResolution::Hour => current + Duration::hours(1),
        TimeResolution::Day => current + Duration::days(1),
        TimeResolution::Month => {
            let new = current
                .replace_month(current.month().next())
                .map_err(|_| DataLayerError::IncorrectParameters)?;
            if new.month() == Month::January {
                new.replace_year(new.year() + 1)
                    .map_err(|_| DataLayerError::IncorrectParameters)?
            } else {
                new
            }
        }
        TimeResolution::Year => current
            .replace_year(current.year() + 1)
            .map_err(|_| DataLayerError::IncorrectParameters)?,
    };
    Ok(new)
}

pub(super) fn floor(
    ts: OffsetDateTime,
    resolution: TimeResolution,
) -> Result<OffsetDateTime, DataLayerError> {
    match resolution {
        TimeResolution::Hour => Ok(ts.truncate_to_hour()),
        TimeResolution::Day => Ok(ts.truncate_to_day()),
        TimeResolution::Month => ts
            .truncate_to_day()
            .replace_day(1)
            .map_err(|_| DataLayerError::IncorrectParameters),
        TimeResolution::Year => ts
            .truncate_to_day()
            .replace_day(1)
            .map_err(|_| DataLayerError::IncorrectParameters)?
            .replace_month(Month::January)
            .map_err(|_| DataLayerError::IncorrectParameters),
    }
}

pub(super) fn ceil(
    ts: OffsetDateTime,
    resolution: TimeResolution,
) -> Result<OffsetDateTime, DataLayerError> {
    let floored = floor(ts, resolution)?;
    next_timestamp(floored, resolution)
}

fn zero_point(ts: OffsetDateTime) -> TimeSeriesPoint {
    TimeSeriesPoint {
        timestamp: ts,
        count: 0,
    }
}

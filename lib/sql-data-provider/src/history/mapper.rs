use one_core::model::history::{
    GetHistoryList, History, IssuerTimelines, OrganisationOperationsCount, OrganisationTimelines,
    TimeSeriesPoint, VerifierTimelines,
};
use one_core::repository::error::DataLayerError;
use one_dto_mapper::try_convert_inner;
use sea_orm::ActiveValue::Set;
use time::{Duration, Month, OffsetDateTime};

use crate::common::calculate_pages_count;
use crate::entity::history;
use crate::entity::history::{HistoryAction, HistoryEntityType};
use crate::history::model::{OrganisationOpsCount, TimeResolution, TimeSeriesRow};

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
    from: Option<OffsetDateTime>,
    to: OffsetDateTime,
) -> Result<OrganisationTimelines, DataLayerError> {
    let resolution = TimeResolution::new(from, to);
    // Align timestamps to start of their respective bucket boundary
    let to = floor(to, resolution)?;

    let mut result = OrganisationTimelines {
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
    };

    let Some(first) = rows.first() else {
        // The empty time series needs to start somewhere. If we're not given a start, fall back to now.
        let from = floor(from.unwrap_or(OffsetDateTime::now_utc()), resolution)?;
        // Empty rows, create zero time series
        fill_missing_zeros(&mut result, resolution, from, to, FillMode::Inclusive)?;
        return Ok(result);
    };
    // Deduce the start of the time series from the first row if no explicit start was given.
    let from = floor(from.unwrap_or(first.timestamp), resolution)?;

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
            // Immediately fill gaps, if any
            fill_missing_zeros(
                &mut result,
                resolution,
                prev_ts,
                row.timestamp,
                FillMode::Exclusive,
            )?;
        }
        prev_timestamp = Some(row.timestamp);
        let point = TimeSeriesPoint {
            timestamp: row.timestamp,
            count: row.count as usize,
        };
        match (row.entity_type, row.action) {
            (HistoryEntityType::Credential, HistoryAction::Offered) => {
                result.issuer.offered.push(point)
            }
            (HistoryEntityType::Credential, HistoryAction::Issued) => {
                result.issuer.issued.push(point)
            }
            (HistoryEntityType::Credential, HistoryAction::Rejected) => {
                result.issuer.rejected.push(point)
            }
            (HistoryEntityType::Credential, HistoryAction::Suspended) => {
                result.issuer.suspended.push(point)
            }
            (HistoryEntityType::Credential, HistoryAction::Reactivated) => {
                result.issuer.reactivated.push(point)
            }
            (HistoryEntityType::Credential, HistoryAction::Revoked) => {
                result.issuer.revoked.push(point)
            }
            (HistoryEntityType::Credential, HistoryAction::Errored) => {
                result.issuer.error.push(point)
            }
            (HistoryEntityType::Proof, HistoryAction::Pending) => {
                result.verifier.pending.push(point)
            }
            (HistoryEntityType::Proof, HistoryAction::Accepted) => {
                result.verifier.accepted.push(point)
            }
            (HistoryEntityType::Proof, HistoryAction::Rejected) => {
                result.verifier.rejected.push(point)
            }
            (HistoryEntityType::Proof, HistoryAction::Errored) => result.verifier.error.push(point),
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
    timelines: &mut OrganisationTimelines,
    resolution: TimeResolution,
    from: OffsetDateTime,
    to: OffsetDateTime,
    mode: FillMode,
) -> Result<(), DataLayerError> {
    let issuer = &mut timelines.issuer;
    fill_zeros(&mut issuer.offered, resolution, from, to, mode)?;
    fill_zeros(&mut issuer.issued, resolution, from, to, mode)?;
    fill_zeros(&mut issuer.rejected, resolution, from, to, mode)?;
    fill_zeros(&mut issuer.suspended, resolution, from, to, mode)?;
    fill_zeros(&mut issuer.reactivated, resolution, from, to, mode)?;
    fill_zeros(&mut issuer.revoked, resolution, from, to, mode)?;
    fill_zeros(&mut issuer.error, resolution, from, to, mode)?;
    let verifier = &mut timelines.verifier;
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
    if limit_reached(&from, &to, mode) {
        // Don't need to fill anything, the requested time range is empty.
        return Ok(());
    }
    let from = if let Some(last_point) = stats.last() {
        last_point.timestamp
    } else {
        stats.push(zero_point(from));
        from
    };
    let mut next_ts = next_timestamp(from, time_resolution)?;
    while !limit_reached(&next_ts, &to, mode) {
        stats.push(zero_point(next_ts));
        next_ts = next_timestamp(next_ts, time_resolution)?;
    }
    Ok(())
}

fn limit_reached(timestamp: &OffsetDateTime, limit: &OffsetDateTime, mode: FillMode) -> bool {
    match mode {
        FillMode::Inclusive => timestamp > limit,
        FillMode::Exclusive => timestamp >= limit,
    }
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

pub(super) fn to_ops_org_count(
    current_counts: &[OrganisationOpsCount],
    prev_counts: Option<&[usize]>,
) -> Result<Vec<OrganisationOperationsCount>, DataLayerError> {
    let Some(prev_counts) = prev_counts else {
        let result = current_counts
            .iter()
            .map(|current| OrganisationOperationsCount {
                organisation_id: current.organisation_id,
                current: current.count as usize,
                previous: None,
            })
            .collect();
        return Ok(result);
    };
    if current_counts.len() != prev_counts.len() {
        return Err(DataLayerError::MappingError);
    }
    let result = current_counts
        .iter()
        .zip(prev_counts.iter())
        .map(|(current, prev)| OrganisationOperationsCount {
            organisation_id: current.organisation_id,
            current: current.count as usize,
            previous: Some(*prev),
        })
        .collect();
    Ok(result)
}

use sea_orm::FromQueryResult;
use shared_types::OrganisationId;
use time::{Duration, OffsetDateTime};

use crate::entity::history::{HistoryAction, HistoryEntityType};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeResolution {
    Hour,
    Day,
    Month,
    Year,
}

impl TimeResolution {
    pub fn new(from: Option<OffsetDateTime>, to: OffsetDateTime) -> Self {
        let Some(from) = from else { return Self::Year };
        let time_diff = to - from;
        match time_diff {
            duration if duration <= Duration::days(1) => Self::Hour,
            duration if duration <= Duration::days(30) => Self::Day,
            duration if duration <= Duration::days(365 * 3) => Self::Month,
            _ => Self::Year,
        }
    }
}

#[derive(Clone, Debug)]
pub struct WindowCount {
    /// Event count in previous time window
    /// Not available if there is no previous window
    pub previous: Option<usize>,
    /// Event count in current time window
    pub current: usize,
}

#[derive(FromQueryResult, Debug)]
pub struct TimeSeriesRow {
    pub timestamp: OffsetDateTime,
    pub entity_type: HistoryEntityType,
    pub action: HistoryAction,
    pub count: i64,
}

#[derive(FromQueryResult, Debug)]
pub struct OrganisationOpsCount {
    pub organisation_id: OrganisationId,
    pub count: i64,
}

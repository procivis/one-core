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
    pub fn new(from: OffsetDateTime, to: OffsetDateTime) -> Self {
        let time_diff = to - from;
        match time_diff {
            duration if duration <= Duration::days(1) => Self::Hour,
            duration if duration <= Duration::days(30) => Self::Day,
            duration if duration <= Duration::days(365) => Self::Month,
            _ => Self::Year,
        }
    }
}

#[derive(FromQueryResult, Debug)]
pub struct TimeSeriesRow {
    pub timestamp: OffsetDateTime,
    pub entity_type: HistoryEntityType,
    pub action: HistoryAction,
    pub count: u32,
}

#[derive(FromQueryResult, Debug)]
pub struct OrganisationOpsCount {
    pub organisation_id: OrganisationId,
    pub count: u32,
}

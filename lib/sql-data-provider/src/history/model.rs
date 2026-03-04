use sea_orm::FromQueryResult;
use shared_types::{CredentialSchemaId, OrganisationId, ProofSchemaId};
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

pub struct PaginatedStats<T> {
    pub current: Vec<T>,
    pub previous: Option<Vec<T>>,
    pub total_items: u64,
}

#[derive(FromQueryResult, Debug, Clone)]
pub struct IssuerStatsRow {
    pub credential_schema_id: CredentialSchemaId,
    pub name: String,
    #[sea_orm(from_alias = "ISSUED")]
    pub issued: i64,
    #[sea_orm(from_alias = "SUSPENDED")]
    pub suspended: i64,
    #[sea_orm(from_alias = "REACTIVATED")]
    pub reactivated: i64,
    #[sea_orm(from_alias = "REVOKED")]
    pub revoked: i64,
    #[sea_orm(from_alias = "ERRORED")]
    pub error: i64,
}

#[derive(FromQueryResult, Debug, Clone)]
pub struct VerifierStatsRow {
    pub proof_schema_id: ProofSchemaId,
    pub name: String,
    #[sea_orm(from_alias = "ACCEPTED")]
    pub accepted: i64,
    #[sea_orm(from_alias = "REJECTED")]
    pub rejected: i64,
    #[sea_orm(from_alias = "ERRORED")]
    pub error: i64,
}

#[derive(FromQueryResult, Debug, Clone)]
pub struct SystemInteractionStatsRow {
    pub organisation_id: OrganisationId,
    #[sea_orm(from_alias = "ISSUED")]
    pub issued: i64,
    #[sea_orm(from_alias = "ACCEPTED")]
    pub accepted: i64,
    pub credential_lifecycle_operation: i64,
    #[sea_orm(from_alias = "ERRORED")]
    pub error: i64,
}

#[derive(FromQueryResult, Debug, Clone)]
pub struct SystemManagementsStatsRow {
    pub organisation_id: OrganisationId,
    #[sea_orm(from_alias = "CREDENTIAL_SCHEMA")]
    pub credential_schema: i64,
    #[sea_orm(from_alias = "PROOF_SCHEMA")]
    pub proof_schema: i64,
    #[sea_orm(from_alias = "IDENTIFIER")]
    pub identifier: i64,
}

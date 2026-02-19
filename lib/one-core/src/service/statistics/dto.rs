use one_dto_mapper::{From, convert_inner};
use shared_types::OrganisationId;
use time::OffsetDateTime;

use crate::model::history::{
    IssuerTimelines, OrganisationOperationsCount, OrganisationStats, OrganisationSummaryStats,
    OrganisationTimelines, SystemOperationsCount, TimeSeriesPoint, VerifierTimelines,
};
pub struct OrganisationStatsRequestDTO {
    pub from: Option<OffsetDateTime>,
    pub to: OffsetDateTime,
    pub organisation_id: OrganisationId,
}

#[derive(Clone, Debug, Eq, PartialEq, From)]
#[from(OrganisationStats)]
pub struct OrganisationStatsResponseDTO {
    #[from(with_fn = convert_inner)]
    pub previous: Option<OrganisationSummaryStatsDTO>,
    pub current: OrganisationSummaryStatsDTO,
    pub timelines: OrganisationTimelinesDTO,
}

#[derive(Clone, Debug, Eq, PartialEq, From)]
#[from(OrganisationSummaryStats)]
pub struct OrganisationSummaryStatsDTO {
    pub issuance_count: usize,
    pub verification_count: usize,
    pub credential_lifecycle_operation_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, From)]
#[from(OrganisationTimelines)]
pub struct OrganisationTimelinesDTO {
    pub issuer: IssuerTimelinesDTO,
    pub verifier: VerifierTimelinesDTO,
}

#[derive(Clone, Debug, Eq, PartialEq, From)]
#[from(IssuerTimelines)]
pub struct IssuerTimelinesDTO {
    #[from(with_fn = convert_inner)]
    pub offered: Vec<TimeSeriesPointDTO>,
    #[from(with_fn = convert_inner)]
    pub issued: Vec<TimeSeriesPointDTO>,
    #[from(with_fn = convert_inner)]
    pub rejected: Vec<TimeSeriesPointDTO>,
    #[from(with_fn = convert_inner)]
    pub suspended: Vec<TimeSeriesPointDTO>,
    #[from(with_fn = convert_inner)]
    pub reactivated: Vec<TimeSeriesPointDTO>,
    #[from(with_fn = convert_inner)]
    pub revoked: Vec<TimeSeriesPointDTO>,
    #[from(with_fn = convert_inner)]
    pub error: Vec<TimeSeriesPointDTO>,
}

#[derive(Clone, Debug, Eq, PartialEq, From)]
#[from(VerifierTimelines)]
pub struct VerifierTimelinesDTO {
    #[from(with_fn = convert_inner)]
    pub pending: Vec<TimeSeriesPointDTO>,
    #[from(with_fn = convert_inner)]
    pub accepted: Vec<TimeSeriesPointDTO>,
    #[from(with_fn = convert_inner)]
    pub rejected: Vec<TimeSeriesPointDTO>,
    #[from(with_fn = convert_inner)]
    pub error: Vec<TimeSeriesPointDTO>,
}

#[derive(Clone, Debug, Eq, PartialEq, From)]
#[from(TimeSeriesPoint)]
pub struct TimeSeriesPointDTO {
    pub timestamp: OffsetDateTime,
    pub count: usize,
}

pub struct SystemStatsRequestDTO {
    pub from: Option<OffsetDateTime>,
    pub to: OffsetDateTime,
    pub organisation_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemStatsResponseDTO {
    pub previous: Option<SystemOperationsCountDTO>,
    pub current: SystemOperationsCountDTO,
    pub top_issuers: Vec<OrganisationOperationsCountDTO>,
    pub top_verifiers: Vec<OrganisationOperationsCountDTO>,
    pub newest_organisations: Vec<NewOrganisationEntryDTO>,
}

#[derive(Clone, Debug, Eq, PartialEq, From)]
#[from(OrganisationOperationsCount)]
pub struct OrganisationOperationsCountDTO {
    #[from(rename = "organisation_id")]
    pub organisation: OrganisationId,
    pub current: usize,
    pub previous: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq, From)]
#[from(SystemOperationsCount)]
pub struct SystemOperationsCountDTO {
    pub issuance_count: usize,
    pub verification_count: usize,
    pub credential_lifecycle_operation_count: usize,
    pub session_token_count: usize,
    pub active_wallet_unit_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewOrganisationEntryDTO {
    pub organisation: OrganisationId,
    pub created_date: OffsetDateTime,
}

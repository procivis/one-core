use one_dto_mapper::{From, convert_inner};
use shared_types::{CredentialSchemaId, OrganisationId, ProofSchemaId};
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::history::{
    IssuerSchemaStats, IssuerStats, IssuerTimelines, OrganisationOperationsCount,
    OrganisationStats, OrganisationSummaryStats, OrganisationTimelines, SystemInteractionCounts,
    SystemInteractionStats, SystemOperationsCount, TimeSeriesPoint, VerifierSchemaStats,
    VerifierStats, VerifierTimelines,
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

pub type GetIssuerStatsResponseDTO = GetListResponse<IssuerSchemaStatsResponseDTO>;

#[derive(Clone, Debug, Eq, PartialEq, From)]
#[from(IssuerSchemaStats)]
pub struct IssuerSchemaStatsResponseDTO {
    pub credential_schema_id: CredentialSchemaId,
    pub credential_schema_name: String,
    pub current: IssuerStatsDTO,
    #[from(with_fn = convert_inner)]
    pub previous: Option<IssuerStatsDTO>,
}

#[derive(Clone, Debug, Eq, PartialEq, From)]
#[from(IssuerStats)]
pub struct IssuerStatsDTO {
    pub issued_count: usize,
    pub suspended_count: usize,
    pub reactivated_count: usize,
    pub revoked_count: usize,
    pub error_count: usize,
}

pub type GetVerifierStatsResponseDTO = GetListResponse<VerifierSchemaStatsResponseDTO>;

#[derive(Clone, Debug, Eq, PartialEq, From)]
#[from(VerifierSchemaStats)]
pub struct VerifierSchemaStatsResponseDTO {
    pub proof_schema_id: ProofSchemaId,
    pub proof_schema_name: String,
    pub current: VerifierStatsDTO,
    #[from(with_fn = convert_inner)]
    pub previous: Option<VerifierStatsDTO>,
}

#[derive(Clone, Debug, Eq, PartialEq, From)]
#[from(VerifierStats)]
pub struct VerifierStatsDTO {
    pub accepted_count: usize,
    pub rejected_count: usize,
    pub error_count: usize,
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

pub type GetSystemInteractionStatsResponseDTO = GetListResponse<SystemInteractionStatsResponseDTO>;

#[derive(Clone, Debug, Eq, PartialEq, From)]
#[from(SystemInteractionStats)]
pub struct SystemInteractionStatsResponseDTO {
    pub organisation_id: OrganisationId,
    pub current: SystemInteractionCountsDTO,
    #[from(with_fn = convert_inner)]
    pub previous: Option<SystemInteractionCountsDTO>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default, From)]
#[from(SystemInteractionCounts)]
pub struct SystemInteractionCountsDTO {
    pub issued_count: usize,
    pub verified_count: usize,
    pub credential_lifecycle_operation_count: usize,
    pub error_count: usize,
}

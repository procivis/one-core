use one_core::service::error::ServiceError;
use one_core::service::statistics::dto::{
    IssuerTimelinesDTO, NewOrganisationEntryDTO, OrganisationOperationsCountDTO,
    OrganisationStatsRequestDTO, OrganisationStatsResponseDTO, OrganisationSummaryStatsDTO,
    OrganisationTimelinesDTO, SystemOperationsCountDTO, SystemStatsResponseDTO, TimeSeriesPointDTO,
    VerifierTimelinesDTO,
};
use one_dto_mapper::{From, TryInto, convert_inner};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use shared_types::OrganisationId;
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};

use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::serialize::front_time;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, TryInto, IntoParams)]
#[try_into(T = OrganisationStatsRequestDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct OrganisationStatsRequestQuery {
    #[try_into(infallible)]
    #[param(nullable = false)]
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub from: Option<OffsetDateTime>,
    #[try_into(infallible)]
    #[serde(deserialize_with = "time::serde::rfc3339::deserialize")]
    pub to: OffsetDateTime,
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    #[param(nullable = false)]
    pub organisation_id: Option<OrganisationId>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, From, ToSchema)]
#[from(OrganisationStatsResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct OrganisationStatsResponseRestDTO {
    #[from(with_fn = convert_inner)]
    pub previous: Option<OrganisationSummaryStatsRestDTO>,
    pub current: OrganisationSummaryStatsRestDTO,
    pub timelines: OrganisationTimelinesRestDTO,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, From, ToSchema)]
#[from(OrganisationSummaryStatsDTO)]
#[serde(rename_all = "camelCase")]
pub struct OrganisationSummaryStatsRestDTO {
    pub issuance_count: usize,
    pub verification_count: usize,
    pub credential_lifecycle_operation_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, From, ToSchema)]
#[from(OrganisationTimelinesDTO)]
#[serde(rename_all = "camelCase")]
pub struct OrganisationTimelinesRestDTO {
    pub issuer: IssuerTimelinesRestDTO,
    pub verifier: VerifierTimelinesRestDTO,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, From, ToSchema)]
#[from(IssuerTimelinesDTO)]
#[serde(rename_all = "camelCase")]
pub struct IssuerTimelinesRestDTO {
    #[from(with_fn = convert_inner)]
    pub offered: Vec<TimeSeriesPointRestDTO>,
    #[from(with_fn = convert_inner)]
    pub issued: Vec<TimeSeriesPointRestDTO>,
    #[from(with_fn = convert_inner)]
    pub rejected: Vec<TimeSeriesPointRestDTO>,
    #[from(with_fn = convert_inner)]
    pub suspended: Vec<TimeSeriesPointRestDTO>,
    #[from(with_fn = convert_inner)]
    pub reactivated: Vec<TimeSeriesPointRestDTO>,
    #[from(with_fn = convert_inner)]
    pub revoked: Vec<TimeSeriesPointRestDTO>,
    #[from(with_fn = convert_inner)]
    pub error: Vec<TimeSeriesPointRestDTO>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, From, ToSchema)]
#[from(VerifierTimelinesDTO)]
#[serde(rename_all = "camelCase")]
pub struct VerifierTimelinesRestDTO {
    #[from(with_fn = convert_inner)]
    pub pending: Vec<TimeSeriesPointRestDTO>,
    #[from(with_fn = convert_inner)]
    pub accepted: Vec<TimeSeriesPointRestDTO>,
    #[from(with_fn = convert_inner)]
    pub rejected: Vec<TimeSeriesPointRestDTO>,
    #[from(with_fn = convert_inner)]
    pub error: Vec<TimeSeriesPointRestDTO>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, From, ToSchema)]
#[from(TimeSeriesPointDTO)]
#[serde(rename_all = "camelCase")]
pub struct TimeSeriesPointRestDTO {
    #[serde(serialize_with = "front_time")]
    pub timestamp: OffsetDateTime,
    pub count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct SystemStatsRequestQuery {
    #[param(nullable = false)]
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub from: Option<OffsetDateTime>,
    #[serde(deserialize_with = "time::serde::rfc3339::deserialize")]
    pub to: OffsetDateTime,
    #[param(nullable = false)]
    pub organisation_count: Option<usize>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, From, ToSchema)]
#[from(SystemStatsResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct SystemStatsResponseRestDTO {
    #[from(with_fn = convert_inner)]
    pub previous: Option<SystemOperationsCountRestDTO>,
    pub current: SystemOperationsCountRestDTO,
    #[from(with_fn = convert_inner)]
    pub top_issuers: Vec<OrganisationOperationsCountRestDTO>,
    #[from(with_fn = convert_inner)]
    pub top_verifiers: Vec<OrganisationOperationsCountRestDTO>,
    #[from(with_fn = convert_inner)]
    pub newest_organisations: Vec<NewOrganisationEntryRestDTO>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, From, ToSchema)]
#[from(SystemOperationsCountDTO)]
#[serde(rename_all = "camelCase")]
pub struct SystemOperationsCountRestDTO {
    pub issuance_count: usize,
    pub verification_count: usize,
    pub credential_lifecycle_operation_count: usize,
    pub session_token_count: usize,
    pub active_wallet_unit_count: usize,
}

#[options_not_nullable]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, From, ToSchema)]
#[from(OrganisationOperationsCountDTO)]
#[serde(rename_all = "camelCase")]
pub struct OrganisationOperationsCountRestDTO {
    pub organisation: OrganisationId,
    pub current: usize,
    pub previous: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, From, ToSchema)]
#[from(NewOrganisationEntryDTO)]
#[serde(rename_all = "camelCase")]
pub struct NewOrganisationEntryRestDTO {
    pub organisation: OrganisationId,
    #[serde(serialize_with = "front_time")]
    pub created_date: OffsetDateTime,
}

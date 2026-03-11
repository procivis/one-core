use one_core::model::history::{
    SortableIssuerStatisticsColumn, SortableSystemInteractionStatisticsColumn,
    SortableSystemManagementStatisticsColumn, SortableVerifierStatisticsColumn,
};
use one_core::service::error::ServiceError;
use one_core::service::statistics::dto::{
    IssuerSchemaStatsResponseDTO, IssuerStatsDTO, IssuerTimelinesDTO, NewOrganisationEntryDTO,
    OrganisationOperationsCountDTO, OrganisationStatsRequestDTO, OrganisationStatsResponseDTO,
    OrganisationSummaryStatsDTO, OrganisationTimelinesDTO, SystemInteractionCountsDTO,
    SystemManagementCountsDTO, SystemOperationsCountDTO, SystemStatsResponseDTO,
    TimeSeriesPointDTO, VerifierSchemaStatsResponseDTO, VerifierStatsDTO, VerifierTimelinesDTO,
};
use one_dto_mapper::{From, Into, TryInto, convert_inner};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use shared_types::{CredentialSchemaId, OrganisationId, ProofSchemaId};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};

use crate::dto::common::ListQueryParamsRest;
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::serialize::front_time;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, TryInto, IntoParams)]
#[try_into(T = OrganisationStatsRequestDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct OrganisationStatsRequestQuery {
    /// Start of the reporting period (inclusive).
    #[try_into(infallible)]
    #[param(nullable = false)]
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub from: Option<OffsetDateTime>,
    /// End of the reporting period (exclusive).
    #[try_into(infallible)]
    #[serde(deserialize_with = "time::serde::rfc3339::deserialize")]
    pub to: OffsetDateTime,
    /// Required when not using STS authentication mode. Specifies the
    /// organizational context for this operation. When using STS
    /// authentication, this value is derived from the token.    
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    #[param(nullable = false)]
    pub organisation_id: Option<OrganisationId>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, From, ToSchema)]
#[from(OrganisationStatsResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct OrganisationStatsResponseRestDTO {
    /// Comparison statistics for the equivalent preceding period.
    #[from(with_fn = convert_inner)]
    pub previous: Option<OrganisationSummaryStatsRestDTO>,
    /// Statistics for the selected reporting period.
    pub current: OrganisationSummaryStatsRestDTO,
    /// Detailed statistics over time for the reporting period. Each
    /// entry contains a timestamp and count; the interval between
    /// timestamps scales with the length of the reporting period.
    pub timelines: OrganisationTimelinesRestDTO,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, From, ToSchema)]
#[from(OrganisationSummaryStatsDTO)]
#[serde(rename_all = "camelCase")]
pub struct OrganisationSummaryStatsRestDTO {
    /// Number of credentials issued in the reporting period.
    pub issuance_count: usize,
    /// Number of credentials verified in the reporting period.
    pub verification_count: usize,
    /// Number of credential suspensions, reactivations, and revocations
    /// in the reporting period.
    pub credential_lifecycle_operation_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, From, ToSchema)]
#[from(OrganisationTimelinesDTO)]
#[serde(rename_all = "camelCase")]
pub struct OrganisationTimelinesRestDTO {
    /// Detailed issuance statistics for the reporting period.
    pub issuer: IssuerTimelinesRestDTO,
    /// Detailed verification statistics for the reporting period.
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

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(SortableIssuerStatisticsColumn)]
pub(crate) enum SortableIssuerStatisticsColumnRestDTO {
    Issued,
    Revoked,
    Suspended,
    Reactivated,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(SortableVerifierStatisticsColumn)]
pub(crate) enum SortableVerifierStatisticsColumnRestDTO {
    Accepted,
    Rejected,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into_params(parameter_in = Query)]
/// Stats per organization aggregated by either credential or proof schema.
pub struct StatsBySchemaFilterParamsRest {
    /// Start of the reporting period (inclusive).
    #[param(nullable = false)]
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub from: Option<OffsetDateTime>,
    /// End of the reporting period (exclusive).
    #[serde(deserialize_with = "time::serde::rfc3339::deserialize")]
    pub to: OffsetDateTime,
    #[param(nullable = false)]
    pub organisation_id: Option<OrganisationId>,
}

pub(crate) type GetIssuerSchemaStatsQueryRest =
    ListQueryParamsRest<StatsBySchemaFilterParamsRest, SortableIssuerStatisticsColumnRestDTO>;

#[options_not_nullable]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, From, ToSchema)]
#[serde(rename_all = "camelCase")]
#[from(IssuerSchemaStatsResponseDTO)]
pub struct IssuerSchemaStatsResponseRestDTO {
    pub credential_schema_id: CredentialSchemaId,
    pub credential_schema_name: String,
    /// Statistics for the selected reporting period.
    pub current: IssuerStatsRestDTO,
    /// Comparison statistics for the equivalent preceding period.
    #[from(with_fn = convert_inner)]
    pub previous: Option<IssuerStatsRestDTO>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, From, ToSchema)]
#[from(IssuerStatsDTO)]
#[serde(rename_all = "camelCase")]
pub struct IssuerStatsRestDTO {
    pub issued_count: usize,
    pub suspended_count: usize,
    pub reactivated_count: usize,
    pub revoked_count: usize,
    pub error_count: usize,
}

pub(crate) type GetVerifierSchemaStatsQueryRest =
    ListQueryParamsRest<StatsBySchemaFilterParamsRest, SortableVerifierStatisticsColumnRestDTO>;

#[options_not_nullable]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, From, ToSchema)]
#[serde(rename_all = "camelCase")]
#[from(VerifierSchemaStatsResponseDTO)]
pub struct VerifierSchemaStatsResponseRestDTO {
    pub proof_schema_id: ProofSchemaId,
    pub proof_schema_name: String,
    /// Statistics for the selected reporting period.
    pub current: VerifierStatsRestDTO,
    /// Comparison statistics for the equivalent preceding period.
    #[from(with_fn = convert_inner)]
    pub previous: Option<VerifierStatsRestDTO>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, From, ToSchema)]
#[serde(rename_all = "camelCase")]
#[from(VerifierStatsDTO)]
pub struct VerifierStatsRestDTO {
    /// Number of successful credential verifications.
    pub accepted_count: usize,
    /// Number of credential verifications rejected.
    pub rejected_count: usize,
    /// Number of credential verifications resulting in error.
    pub error_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct SystemStatsRequestQuery {
    /// Start of the reporting period (inclusive).
    #[param(nullable = false)]
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub from: Option<OffsetDateTime>,
    /// End of the reporting period (exclusive).
    #[serde(deserialize_with = "time::serde::rfc3339::deserialize")]
    pub to: OffsetDateTime,
    /// Maximum number of organizations to include in `topIssuers`,
    /// `topVerifiers`, and `newestOrganisations`. Does not affect
    /// system-wide totals in `current` and `previous`.
    #[param(nullable = false)]
    pub organisation_count: Option<usize>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, From, ToSchema)]
#[from(SystemStatsResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct SystemStatsResponseRestDTO {
    /// Comparison statistics for the equivalent preceding period.
    #[from(with_fn = convert_inner)]
    pub previous: Option<SystemOperationsCountRestDTO>,
    /// System-wide statistics for the reporting period.
    pub current: SystemOperationsCountRestDTO,
    /// Organizations with the highest issuance counts for the reporting
    /// period, randed in descending order.
    #[from(with_fn = convert_inner)]
    pub top_issuers: Vec<OrganisationOperationsCountRestDTO>,
    /// Organizations with the highest verification counts for the
    /// reporting period, randed in descending order.    
    #[from(with_fn = convert_inner)]
    pub top_verifiers: Vec<OrganisationOperationsCountRestDTO>,
    /// Most recently created organizations, ranked by creation date.
    #[from(with_fn = convert_inner)]
    pub newest_organisations: Vec<NewOrganisationEntryRestDTO>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, From, ToSchema)]
#[from(SystemOperationsCountDTO)]
#[serde(rename_all = "camelCase")]
pub struct SystemOperationsCountRestDTO {
    /// Number of credentials issued across all organizations for the
    /// reporting period.
    pub issuance_count: usize,
    /// Number of credential verifications across all organizations
    /// for the reporting period.
    pub verification_count: usize,
    /// Number of credential suspensions, reactivations, and revocations
    /// across all organizations for the reporting period.
    pub credential_lifecycle_operation_count: usize,
    /// Number of session tokens created, reflecting user activity
    /// levels.
    pub session_token_count: usize,
    /// Number of wallet units with status `active` for the
    /// reporting period.
    pub active_wallet_unit_count: usize,
}

#[options_not_nullable]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, From, ToSchema)]
#[from(OrganisationOperationsCountDTO)]
#[serde(rename_all = "camelCase")]
pub struct OrganisationOperationsCountRestDTO {
    pub organisation: OrganisationId,
    /// Issuance (or verification) count for the reporting period.
    pub current: usize,
    /// Issuance (or verification) count for the equivalent preceding
    /// period.
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

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(SortableSystemInteractionStatisticsColumn)]
pub(crate) enum SortableSystemInteractionStatisticsColumnRestDTO {
    Issued,
    Verified,
    CredentialLifecycleOperation,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct SystemStatsFilterParamsRest {
    /// Start of the reporting period (inclusive).
    #[param(nullable = false)]
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub from: Option<OffsetDateTime>,
    /// End of the reporting period (exclusive).
    #[serde(deserialize_with = "time::serde::rfc3339::deserialize")]
    pub to: OffsetDateTime,
}

pub(crate) type GetSystemInteractionStatsQueryRest = ListQueryParamsRest<
    SystemStatsFilterParamsRest,
    SortableSystemInteractionStatisticsColumnRestDTO,
>;

#[options_not_nullable]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SystemInteractionStatsResponseRestDTO {
    pub organisation_id: OrganisationId,
    /// Statistics for the selected reporting period.
    pub current: SystemInteractionCountsRestDTO,
    /// Comparison statistics for the equivalent preceding period.
    pub previous: Option<SystemInteractionCountsRestDTO>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, From, ToSchema)]
#[serde(rename_all = "camelCase")]
#[from(SystemInteractionCountsDTO)]
pub struct SystemInteractionCountsRestDTO {
    /// Number of credentials issued in the reporting period.    
    pub issued_count: usize,
    /// Number of credentials verified in the reporting period.    
    pub verified_count: usize,
    /// Number of credential suspensions, reactivations, and revocations
    /// in the reporting period.    
    pub credential_lifecycle_operation_count: usize,
    /// Number of credential interactions resulting in an error
    /// in the reporting period.
    pub error_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(SortableSystemManagementStatisticsColumn)]
pub(crate) enum SortableSystemManagementStatisticsColumnRestDTO {
    CredentialSchema,
    ProofSchema,
    Identifier,
}

pub(crate) type GetSystemManagementStatsQueryRest = ListQueryParamsRest<
    SystemStatsFilterParamsRest,
    SortableSystemManagementStatisticsColumnRestDTO,
>;

#[options_not_nullable]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SystemManagementStatsResponseRestDTO {
    pub organisation_id: OrganisationId,
    /// Statistics for the selected reporting period.
    pub current: SystemManagementCountsRestDTO,
    /// Comparison statistics for the equivalent preceding period.
    pub previous: Option<SystemManagementCountsRestDTO>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, From, ToSchema)]
#[serde(rename_all = "camelCase")]
#[from(SystemManagementCountsDTO)]
pub struct SystemManagementCountsRestDTO {
    pub credential_schema_created_count: usize,
    pub proof_schema_created_count: usize,
    pub identifier_created_count: usize,
}

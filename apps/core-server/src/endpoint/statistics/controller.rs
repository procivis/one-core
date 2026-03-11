use axum::extract::State;
use axum_extra::extract::WithRejection;
use one_core::error::ContextWithErrorCode;
use proc_macros::endpoint;
use shared_types::Permission;

use super::dto::{
    GetIssuerSchemaStatsQueryRest, GetSystemInteractionStatsQueryRest,
    GetSystemManagementStatsQueryRest, GetVerifierSchemaStatsQueryRest,
    OrganisationStatsRequestQuery, OrganisationStatsResponseRestDTO, SystemStatsRequestQuery,
    SystemStatsResponseRestDTO,
};
use crate::dto::common::{
    GetIssuerStatsResponseRestDTO, GetSystemInteractionStatsResponseRestDTO,
    GetSystemManagementStatsResponseRestDTO, GetVerifierStatsResponseRestDTO,
};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::dto::response::OkOrErrorResponse;
use crate::endpoint::statistics::mapper::{
    map_to_issuer_stats_queries, map_to_system_interaction_stats_queries,
    map_to_system_management_stats_queries, map_to_verifier_stats_queries,
};
use crate::extractor::Qs;
use crate::router::AppState;

#[endpoint(
    permissions = [Permission::DashboardDetail],
    get,
    path = "/api/statistics/v1/dashboard",
    params(OrganisationStatsRequestQuery),
    responses(OkOrErrorResponse<OrganisationStatsResponseRestDTO>),
    tag = "statistics",
    security(
        ("bearer" = [])
    ),
    summary = "Organization statistics",
    description = indoc::formatdoc! {"
        Retrieve issuance and verification statistics for an organization,
        including detailed timelines.
    "},
)]
pub(crate) async fn organisation_statistics(
    state: State<AppState>,
    WithRejection(Qs(request), _): WithRejection<
        Qs<OrganisationStatsRequestQuery>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<OrganisationStatsResponseRestDTO> {
    let result = async {
        state
            .core
            .statistics_service
            .organisation_stats(request.try_into().error_while("converting request dto")?)
            .await
    }
    .await;
    OkOrErrorResponse::from_result(result, state, "getting organisation statistics")
}

#[endpoint(
    permissions = [Permission::DashboardDetail],
    get,
    path = "/api/statistics/v1/dashboard/issuer",
    params(GetIssuerSchemaStatsQueryRest),
    responses(OkOrErrorResponse<GetIssuerStatsResponseRestDTO>),
    tag = "statistics",
    security(
        ("bearer" = [])
    ),
    summary = "Issuer statistics",
    description = indoc::formatdoc! {"
        Retrieve credential issuance, revocation, suspension and
        reactivation statistics for an organization, including detailed
        timelines.
    "},
)]
pub(crate) async fn issuer_statistics(
    state: State<AppState>,
    WithRejection(Qs(request), _): WithRejection<
        Qs<GetIssuerSchemaStatsQueryRest>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<GetIssuerStatsResponseRestDTO> {
    let result = async {
        let organisation_id = fallback_organisation_id_from_session(request.filter.organisation_id)
            .error_while("mapping organisation from session")?;
        let (current, prev) = map_to_issuer_stats_queries(request).error_while("mapping query")?;
        state
            .core
            .statistics_service
            .issuer_stats(&organisation_id, current, prev)
            .await
    }
    .await;
    OkOrErrorResponse::from_result(result, state, "getting organisation statistics")
}

#[endpoint(
    permissions = [Permission::DashboardDetail],
    get,
    path = "/api/statistics/v1/dashboard/verifier",
    params(GetVerifierSchemaStatsQueryRest),
    responses(OkOrErrorResponse<GetVerifierStatsResponseRestDTO>),
    tag = "statistics",
    security(
        ("bearer" = [])
    ),
    summary = "Verifier statistics",
    description = indoc::formatdoc! {"
        Retrieve proof acceptance and rejection statistics for an organization,
        including detailed timelines.
    "},
)]
pub(crate) async fn verifier_statistics(
    state: State<AppState>,
    WithRejection(Qs(request), _): WithRejection<
        Qs<GetVerifierSchemaStatsQueryRest>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<GetVerifierStatsResponseRestDTO> {
    let result = async {
        let organisation_id = fallback_organisation_id_from_session(request.filter.organisation_id)
            .error_while("mapping organisation from session")?;
        let (current, prev) =
            map_to_verifier_stats_queries(request).error_while("mapping query")?;
        state
            .core
            .statistics_service
            .verifier_stats(&organisation_id, current, prev)
            .await
    }
    .await;
    OkOrErrorResponse::from_result(result, state, "getting organisation statistics")
}

#[endpoint(
    permissions = [Permission::SystemDashboardDetail],
    get,
    path = "/api/statistics/v1/dashboard/system",
    params(SystemStatsRequestQuery),
    responses(OkOrErrorResponse<SystemStatsResponseRestDTO>),
    tag = "statistics",
    security(
        ("bearer" = [])
    ),
    summary = "System statistics",
    description = indoc::formatdoc! {"
        Retrieve system-wide statistics across all organizations, including
        top issuers and verifiers, active wallet units, and recently added
        organizations.
    "},
)]
pub(crate) async fn system_statistics(
    state: State<AppState>,
    WithRejection(Qs(request), _): WithRejection<Qs<SystemStatsRequestQuery>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<SystemStatsResponseRestDTO> {
    let result = state
        .core
        .statistics_service
        .system_stats(request.into())
        .await;
    OkOrErrorResponse::from_result(result, state, "getting system statistics")
}

#[endpoint(
    permissions = [Permission::SystemDashboardDetail],
    get,
    path = "/api/statistics/v1/dashboard/system/interaction",
    params(GetSystemInteractionStatsQueryRest),
    responses(OkOrErrorResponse<GetSystemInteractionStatsResponseRestDTO>),
    tag = "statistics",
    security(
        ("bearer" = [])
    ),
    summary = "System interaction statistics",
    description = indoc::formatdoc! {"
        Retrieve system-wide interaction statistics across all organizations,
        including issuance, verification and lifecycle operation counts.
    "},
)]
pub(crate) async fn system_interaction_statistics(
    state: State<AppState>,
    WithRejection(Qs(request), _): WithRejection<
        Qs<GetSystemInteractionStatsQueryRest>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<GetSystemInteractionStatsResponseRestDTO> {
    let result = async {
        let (current, prev) =
            map_to_system_interaction_stats_queries(request).error_while("mapping query")?;
        state
            .core
            .statistics_service
            .system_interaction_stats(current, prev)
            .await
    }
    .await;
    OkOrErrorResponse::from_result(result, state, "getting system interaction statistics")
}

#[endpoint(
    permissions = [Permission::SystemDashboardDetail],
    get,
    path = "/api/statistics/v1/dashboard/system/management",
    params(GetSystemManagementStatsQueryRest),
    responses(OkOrErrorResponse<GetSystemManagementStatsResponseRestDTO>),
    tag = "statistics",
    security(
        ("bearer" = [])
    ),
    summary = "System management statistics",
    description = indoc::formatdoc! {"
        Retrieve system-wide statistics across all organizations,
        including counts of created credential schemas, proof schemas and
        identifiers.
    "},
)]
pub(crate) async fn system_management_statistics(
    state: State<AppState>,
    WithRejection(Qs(request), _): WithRejection<
        Qs<GetSystemManagementStatsQueryRest>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<GetSystemManagementStatsResponseRestDTO> {
    let result = async {
        let (current, prev) =
            map_to_system_management_stats_queries(request).error_while("mapping query")?;
        state
            .core
            .statistics_service
            .system_management_stats(current, prev)
            .await
    }
    .await;
    OkOrErrorResponse::from_result(result, state, "getting system management statistics")
}

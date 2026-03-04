use axum::extract::State;
use axum_extra::extract::WithRejection;
use one_core::error::ContextWithErrorCode;
use proc_macros::require_permissions;
use shared_types::Permission;

use super::dto::{
    GetSchemaStatsQueryRest, OrganisationStatsRequestQuery, OrganisationStatsResponseRestDTO,
    SystemStatsRequestQuery, SystemStatsResponseRestDTO,
};
use crate::dto::common::GetIssuerStatsResponseRestDTO;
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::dto::response::OkOrErrorResponse;
use crate::endpoint::statistics::mapper::map_to_current_and_prev;
use crate::extractor::Qs;
use crate::router::AppState;

#[utoipa::path(
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
#[require_permissions(Permission::DashboardDetail)]
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

#[utoipa::path(
    get,
    path = "/api/statistics/v1/dashboard/issuer",
    params(GetSchemaStatsQueryRest),
    responses(OkOrErrorResponse<GetIssuerStatsResponseRestDTO>),
    tag = "statistics",
    security(
        ("bearer" = [])
    ),
    summary = "Organisation issuer statistics",
    description = indoc::formatdoc! {"
        Retrieve issuer statistics for a specific organisation.
    "},
)]
#[require_permissions(Permission::DashboardDetail)]
pub(crate) async fn issuer_statistics(
    state: State<AppState>,
    WithRejection(Qs(request), _): WithRejection<Qs<GetSchemaStatsQueryRest>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetIssuerStatsResponseRestDTO> {
    let result = async {
        let organisation_id = fallback_organisation_id_from_session(request.filter.organisation_id)
            .error_while("mapping organisation from session")?;
        let (current, prev) = map_to_current_and_prev(request).error_while("mapping query")?;
        state
            .core
            .statistics_service
            .issuer_stats(&organisation_id, current, prev)
            .await
    }
    .await;
    OkOrErrorResponse::from_result(result, state, "getting organisation statistics")
}

#[utoipa::path(
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
#[require_permissions(Permission::SystemDashboardDetail)]
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

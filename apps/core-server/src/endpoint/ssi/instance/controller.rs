use axum::Json;
use axum::extract::{Path, State};
use axum_extra::TypedHeader;
use axum_extra::extract::WithRejection;
use headers::Authorization;
use headers::authorization::Bearer;
use proc_macros::endpoint;
use shared_types::ManagedInstanceId;

use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{CreatedOrErrorResponse, OkOrErrorResponse};
use crate::endpoint::ssi::instance::dto::RegisterInstanceRequestRestDTO;
use crate::endpoint::ssi::wallet_provider::dto::{
    IssueWalletUnitAttestationRequestRestDTO, IssueWalletUnitAttestationResponseRestDTO,
    RegisterWalletUnitResponseRestDTO, WalletUnitActivationRequestRestDTO,
    WalletUnitActivationResponseRestDTO,
};
use crate::router::AppState;

#[endpoint(
    permissions = [],
    post,
    path = "/ssi/instance/v1",
    request_body = RegisterInstanceRequestRestDTO,
    responses(CreatedOrErrorResponse<RegisterWalletUnitResponseRestDTO>),
    tag = "ssi",
    summary = "Register instance",
    description = indoc::formatdoc! {"
        Register new instance.
    "},
)]
pub(crate) async fn register_instance(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<RegisterInstanceRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<RegisterWalletUnitResponseRestDTO> {
    let result = state
        .core
        .managed_instance_service
        .register_instance(request.into())
        .await;
    CreatedOrErrorResponse::from_result(result, state, "registering instance")
}

#[endpoint(
    permissions = [],
    post,
    path = "/ssi/instance/v1/{id}/activate",
    params(
        ("id" = ManagedInstanceId, Path, description = "Instance id")
    ),
    request_body = WalletUnitActivationRequestRestDTO,
    responses(OkOrErrorResponse<WalletUnitActivationResponseRestDTO>),
    tag = "ssi",
    summary = "Activates instance",
    description = indoc::formatdoc! {"
        Activates instance.
    "},
)]
pub(crate) async fn activate_instance(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<ManagedInstanceId>, ErrorResponseRestDTO>,
    WithRejection(Json(request), _): WithRejection<
        Json<WalletUnitActivationRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<WalletUnitActivationResponseRestDTO> {
    let result = state
        .core
        .managed_instance_service
        .activate_instance(id, request.into())
        .await;
    OkOrErrorResponse::from_result(result, state, "activating instance")
}

#[endpoint(
    permissions = [],
    post,
    path = "/ssi/instance/v1/{id}/issue-attestation",
    params(
        ("id" = ManagedInstanceId, Path, description = "Instance id")
    ),
    request_body = IssueWalletUnitAttestationRequestRestDTO,
    responses(OkOrErrorResponse<IssueWalletUnitAttestationResponseRestDTO>),
    security(
        ("wallet-unit" = [])
    ),
    tag = "ssi",
    summary = "Issues instance attestations",
    description = indoc::formatdoc! {"
        Issue wallet app and wallet unit attestations.
    "},
)]
pub(crate) async fn issue_instance_attestation(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<ManagedInstanceId>, ErrorResponseRestDTO>,
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
    WithRejection(Json(request), _): WithRejection<
        Json<IssueWalletUnitAttestationRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<IssueWalletUnitAttestationResponseRestDTO> {
    let result = state
        .core
        .managed_instance_service
        .issue_attestation(id, bearer.token(), request.into())
        .await;
    OkOrErrorResponse::from_result(result, state, "issuing instance attestation")
}

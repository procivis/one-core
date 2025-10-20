use axum::Json;
use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use shared_types::WalletUnitId;

use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::OkOrErrorResponse;
use crate::endpoint::ssi::wallet_provider::dto::{
    RefreshWalletUnitRequestRestDTO, RefreshWalletUnitResponseRestDTO,
    RegisterWalletUnitRequestRestDTO, RegisterWalletUnitResponseRestDTO,
    WalletUnitActivationRequestRestDTO, WalletUnitActivationResponseRestDTO,
};
use crate::router::AppState;

#[utoipa::path(
    post,
    path = "/ssi/wallet-unit/v1",
    request_body = RegisterWalletUnitRequestRestDTO,
    responses(OkOrErrorResponse<RegisterWalletUnitResponseRestDTO>),
    tag = "ssi",
    summary = "Register wallet unit and generate attestation.",
    description = indoc::formatdoc! {"
        Register new wallet unit. Generates attestation based on parameters.
    "},
)]
pub(crate) async fn register_wallet_unit(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<RegisterWalletUnitRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<RegisterWalletUnitResponseRestDTO> {
    let result = state
        .core
        .wallet_provider_service
        .register_wallet_unit(request.into())
        .await;
    OkOrErrorResponse::from_result(result, state, "register wallet unit")
}

#[utoipa::path(
    post,
    path = "/ssi/wallet-unit/v1/{id}/activate",
    params(
        ("id" = WalletUnitId, Path, description = "Wallet unit id")
    ),
    request_body = WalletUnitActivationRequestRestDTO,
    responses(OkOrErrorResponse<WalletUnitActivationResponseRestDTO>),
    tag = "ssi",
    summary = "Activates wallet unit.",
    description = indoc::formatdoc! {"
        Activates wallet unit.
    "},
)]
pub(crate) async fn activate_wallet_unit(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<WalletUnitId>, ErrorResponseRestDTO>,
    WithRejection(Json(request), _): WithRejection<
        Json<WalletUnitActivationRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<WalletUnitActivationResponseRestDTO> {
    let result = state
        .core
        .wallet_provider_service
        .activate_wallet_unit(id, request.into())
        .await;
    OkOrErrorResponse::from_result(result, state, "activate wallet unit")
}

#[utoipa::path(
    post,
    path = "/ssi/wallet-unit/v1/{id}/refresh",
    params(
        ("id" = WalletUnitId, Path, description = "Wallet unit id")
    ),
    request_body = RefreshWalletUnitRequestRestDTO,
    responses(OkOrErrorResponse<RefreshWalletUnitResponseRestDTO>),
    tag = "ssi",
    summary = "Refreshes wallet unit attestation.",
    description = indoc::formatdoc! {"
        Refreshes wallet unit attestation.
    "},
)]
pub(crate) async fn refresh_wallet_unit(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<WalletUnitId>, ErrorResponseRestDTO>,
    WithRejection(Json(request), _): WithRejection<
        Json<RefreshWalletUnitRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<RefreshWalletUnitResponseRestDTO> {
    let result = state
        .core
        .wallet_provider_service
        .refresh_wallet_unit(id, request.into())
        .await;
    OkOrErrorResponse::from_result(result, state, "register wallet unit")
}

use axum::Json;
use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use proc_macros::require_permissions;
use shared_types::{HolderWalletUnitId, Permission};

use crate::dto::common::EntityResponseRestDTO;
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{CreatedOrErrorResponse, EmptyOrErrorResponse, OkOrErrorResponse};
use crate::endpoint::holder_wallet_unit::dto::{
    HolderRegisterWalletUnitRequestRestDTO, HolderWalletUnitDetailRestDTO,
};
use crate::router::AppState;

#[utoipa::path(
    post,
    path = "/api/holder-wallet-unit/v1",
    request_body = HolderRegisterWalletUnitRequestRestDTO,
    responses(CreatedOrErrorResponse<EntityResponseRestDTO>),
    tag = "holder_wallet_unit",
    security(
        ("bearer" = [])
    ),
    summary = "Register with a Wallet Provider",
    description = indoc::formatdoc! {"
        Register a wallet unit with a Wallet Provider.
    "},
)]
#[require_permissions(Permission::HolderWalletUnitRegister)]
pub(crate) async fn wallet_unit_holder_register(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<HolderRegisterWalletUnitRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let result = async {
        state
            .core
            .wallet_unit_service
            .holder_register(request.try_into()?)
            .await
    }
    .await;
    CreatedOrErrorResponse::from_result(result, state, "register wallet unit")
}

#[utoipa::path(
    get,
    path = "/api/holder-wallet-unit/v1/{id}",
    responses(OkOrErrorResponse<HolderWalletUnitDetailRestDTO>),
    params(
        ("id" = HolderWalletUnitId, Path, description = "Wallet Unit ID")
    ),
    tag = "holder_wallet_unit",
    security(
        ("bearer" = [])
    ),
    summary = "Retrieve wallet registration details",
    description = "Retrieve details of a wallet unit's registration from the Wallet Provider.",
)]
#[require_permissions(Permission::HolderWalletUnitDetail)]
pub(crate) async fn wallet_unit_holder_details(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<HolderWalletUnitId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<HolderWalletUnitDetailRestDTO> {
    let result = state
        .core
        .wallet_unit_service
        .get_wallet_unit_details(id)
        .await;

    OkOrErrorResponse::from_result_fallible(result, state, "get holder wallet unit")
}

#[utoipa::path(
    post,
    path = "/api/holder-wallet-unit/v1/{id}/status",
    responses(EmptyOrErrorResponse),
    params(
        ("id" = HolderWalletUnitId, Path, description = "Wallet Unit ID")
    ),
    tag = "holder_wallet_unit",
    security(
        ("bearer" = [])
    ),
    summary = "Check wallet status",
    description = indoc::formatdoc! {
        "Check the status of a wallet unit. Active units return `204`. Revoked units return an error."},
)]
#[require_permissions(Permission::HolderWalletUnitDetail)]
pub(crate) async fn wallet_unit_holder_status(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<HolderWalletUnitId>, ErrorResponseRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .wallet_unit_service
        .holder_wallet_unit_status(id)
        .await;

    EmptyOrErrorResponse::from_result(result, state, "holder wallet unit status check")
}

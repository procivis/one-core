use axum::Json;
use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use one_core::error::ContextWithErrorCode;
use one_core::service::error::ServiceError;
use proc_macros::endpoint;
use shared_types::{HolderWalletUnitId, Permission};

use super::dto::{
    EditHolderWalletUnitRequestRestDTO, HolderRegisterWalletUnitRequestRestDTO,
    HolderRegisterWalletUnitResponseRestDTO, HolderWalletUnitDetailRestDTO,
};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{CreatedOrErrorResponse, EmptyOrErrorResponse, OkOrErrorResponse};
use crate::router::AppState;

#[endpoint(
    permissions = [Permission::HolderWalletUnitRegister],
    post,
    path = "/api/holder-wallet-unit/v1",
    request_body = HolderRegisterWalletUnitRequestRestDTO,
    responses(CreatedOrErrorResponse<HolderRegisterWalletUnitResponseRestDTO>),
    tag = "holder_wallet_unit",
    security(
        ("bearer" = [])
    ),
    summary = "Register with a Wallet Provider",
    description = indoc::formatdoc! {"
        Register a wallet unit with a Wallet Provider.
    "},
)]
pub(crate) async fn wallet_unit_holder_register(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<HolderRegisterWalletUnitRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<HolderRegisterWalletUnitResponseRestDTO> {
    let result = async {
        Ok::<_, ServiceError>(
            state
                .core
                .wallet_unit_service
                .holder_register(request.try_into()?)
                .await
                .error_while("registering holder wallet unit")?,
        )
    }
    .await;
    CreatedOrErrorResponse::from_result(result, state, "register wallet unit")
}

#[endpoint(
    permissions = [Permission::HolderWalletUnitDetail],
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
pub(crate) async fn wallet_unit_holder_details(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<HolderWalletUnitId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<HolderWalletUnitDetailRestDTO> {
    let result = state
        .core
        .wallet_unit_service
        .holder_get_wallet_unit_details(id)
        .await
        .error_while("getting holder wallet unit")
        .map_err(ServiceError::from);

    OkOrErrorResponse::from_result_fallible(result, state, "getting holder wallet unit")
}

#[endpoint(
    permissions = [Permission::HolderWalletUnitDetail],
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

#[endpoint(
    permissions = [Permission::HolderWalletUnitEdit],
    patch,
    path = "/api/holder-wallet-unit/v1/{id}",
    request_body = EditHolderWalletUnitRequestRestDTO,
    responses(EmptyOrErrorResponse),
    params(
        ("id" = HolderWalletUnitId, Path, description = "Wallet Unit ID")
    ),
    tag = "holder_wallet_unit",
    security(
        ("bearer" = [])
    ),
    summary = "Edit wallet settings",
    description = "Modify wallet settings.",
)]
pub(crate) async fn edit_holder_wallet_unit(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<HolderWalletUnitId>, ErrorResponseRestDTO>,
    WithRejection(Json(request), _): WithRejection<
        Json<EditHolderWalletUnitRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .wallet_unit_service
        .edit_holder_wallet_unit(id, request.into())
        .await;

    EmptyOrErrorResponse::from_result(result, state, "editing holder wallet unit")
}

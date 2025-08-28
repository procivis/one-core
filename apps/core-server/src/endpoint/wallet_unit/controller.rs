use axum::Json;
use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use shared_types::OrganisationId;

use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{EmptyOrErrorResponse, OkOrErrorResponse};
use crate::endpoint::wallet_unit::dto::{
    HolderRefreshWalletUnitRequestRestDTO, HolderRegisterWalletUnitRequestRestDTO,
    HolderWalletUnitAttestationResponseRestDTO,
};
use crate::router::AppState;

#[utoipa::path(
    post,
    path = "/api/wallet-unit/v1/holder-register",
    request_body = HolderRegisterWalletUnitRequestRestDTO,
    responses(EmptyOrErrorResponse),
    tag = "wallet_unit",
    security(
        ("bearer" = [])
    ),
    summary = "Register wallet unit and fetch attestation.",
    description = indoc::formatdoc! {"
        Register wallet unit and fetch attestation.
    "},
)]
pub(crate) async fn wallet_unit_holder_register(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<HolderRegisterWalletUnitRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .wallet_unit_service
        .holder_register(request.into())
        .await;
    EmptyOrErrorResponse::from_result(result, state, "register wallet unit")
}

#[utoipa::path(
    post,
    path = "/api/wallet-unit/v1/holder-refresh",
    request_body = HolderRefreshWalletUnitRequestRestDTO,
    responses(EmptyOrErrorResponse),
    tag = "wallet_unit",
    security(
        ("bearer" = [])
    ),
    summary = "Refreshes wallet unit attestation.",
    description = indoc::formatdoc! {"
        Refreshes wallet unit attestation.
    "},
)]
pub(crate) async fn wallet_unit_holder_refresh(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<HolderRefreshWalletUnitRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .wallet_unit_service
        .holder_refresh(request.into())
        .await;
    EmptyOrErrorResponse::from_result(result, state, "refresh wallet unit")
}

#[utoipa::path(
    get,
    path = "/api/wallet-unit/v1/holder-attestation",
    params(
        ("organisationId" = OrganisationId, Path, description = "Organization id")
    ),
    responses(
        (status = 200, description = "OK", body = HolderWalletUnitAttestationResponseRestDTO),
        (status = 404, description = "Wallet unit attestation not found"),
        (status = 500, description = "Server error"),
    ),
    security(
        ("bearer" = [])
    ),
    tag = "wallet_unit",
    summary = "Retrieve wallet unit attestation.",
    description = indoc::formatdoc! {"
        Retrieve wallet unit attestation.
    "},
)]
pub(crate) async fn wallet_unit_holder_attestation(
    state: State<AppState>,
    WithRejection(Path(organisation_id), _): WithRejection<
        Path<OrganisationId>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<HolderWalletUnitAttestationResponseRestDTO> {
    let result = state
        .core
        .wallet_unit_service
        .holder_attestation(organisation_id)
        .await;
    OkOrErrorResponse::from_result(result, state, "get wallet unit attestation")
}

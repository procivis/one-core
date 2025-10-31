use axum::Json;
use axum::extract::{Path, State};
use axum_extra::TypedHeader;
use axum_extra::extract::WithRejection;
use headers::Authorization;
use headers::authorization::Bearer;
use shared_types::WalletUnitId;

use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{CreatedOrErrorResponse, EmptyOrErrorResponse, OkOrErrorResponse};
use crate::endpoint::ssi::wallet_provider::dto::{
    IssueWalletUnitAttestationRequestRestDTO, IssueWalletUnitAttestationResponseRestDTO,
    RegisterWalletUnitRequestRestDTO, RegisterWalletUnitResponseRestDTO,
    WalletProviderMetadataResponseRestDTO, WalletUnitActivationRequestRestDTO,
};
use crate::router::AppState;

#[utoipa::path(
    post,
    path = "/ssi/wallet-unit/v1",
    request_body = RegisterWalletUnitRequestRestDTO,
    responses(CreatedOrErrorResponse<RegisterWalletUnitResponseRestDTO>),
    tag = "ssi",
    summary = "Register wallet unit.",
    description = indoc::formatdoc! {"
        Register new wallet unit.
    "},
)]
pub(crate) async fn register_wallet_unit(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<RegisterWalletUnitRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<RegisterWalletUnitResponseRestDTO> {
    let result = state
        .core
        .wallet_provider_service
        .register_wallet_unit(request.into())
        .await;
    CreatedOrErrorResponse::from_result(result, state, "registering wallet unit")
}

#[utoipa::path(
    post,
    path = "/ssi/wallet-unit/v1/{id}/activate",
    params(
        ("id" = WalletUnitId, Path, description = "Wallet unit id")
    ),
    request_body = WalletUnitActivationRequestRestDTO,
    responses(EmptyOrErrorResponse),
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
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .wallet_provider_service
        .activate_wallet_unit(id, request.into())
        .await;
    EmptyOrErrorResponse::from_result(result, state, "activating wallet unit")
}

#[utoipa::path(
    post,
    path = "/ssi/wallet-unit/v1/{id}/issue-attestation",
    params(
        ("id" = WalletUnitId, Path, description = "Wallet unit id")
    ),
    request_body = IssueWalletUnitAttestationRequestRestDTO,
    responses(OkOrErrorResponse<IssueWalletUnitAttestationResponseRestDTO>),
    security(
        ("wallet-unit" = [])
    ),
    tag = "ssi",
    summary = "Issues wallet attestations.",
    description = indoc::formatdoc! {"
        Issue wallet app and wallet unit attestations.
    "},
)]
pub(crate) async fn issue_wallet_unit_attestation(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<WalletUnitId>, ErrorResponseRestDTO>,
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
    WithRejection(Json(request), _): WithRejection<
        Json<IssueWalletUnitAttestationRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<IssueWalletUnitAttestationResponseRestDTO> {
    let result = state
        .core
        .wallet_provider_service
        .issue_attestation(id, bearer.token(), request.into())
        .await;
    OkOrErrorResponse::from_result(result, state, "issuing wallet attestation")
}

#[utoipa::path(
    get,
    path = "/ssi/wallet-provider/v1/{walletProvider}",
    params(
        ("walletProvider" = String, Path, description = "Wallet provider")
    ),
    responses(OkOrErrorResponse<WalletProviderMetadataResponseRestDTO>),
    tag = "ssi",
    summary = "Returns metadata of given wallet provider",
    description = indoc::formatdoc! {"
        Returns metadata of given wallet provider.
    "},
)]
pub(crate) async fn get_wallet_provider_metadata(
    state: State<AppState>,
    WithRejection(Path(wallet_provider), _): WithRejection<Path<String>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<WalletProviderMetadataResponseRestDTO> {
    let result = state
        .core
        .wallet_provider_service
        .get_wallet_provider_metadata(wallet_provider)
        .await;
    OkOrErrorResponse::from_result(result, state, "getting wallet provider metadata")
}

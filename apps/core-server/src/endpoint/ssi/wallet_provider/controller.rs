use axum::Json;
use axum::extract::{Path, State};
use axum_extra::TypedHeader;
use axum_extra::extract::WithRejection;
use headers::Authorization;
use headers::authorization::Bearer;
use proc_macros::endpoint;
use shared_types::ManagedInstanceId;

use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{CreatedOrErrorResponse, EmptyOrErrorResponse, OkOrErrorResponse};
use crate::endpoint::ssi::wallet_provider::dto::{
    IssueWalletUnitAttestationRequestRestDTO, IssueWalletUnitAttestationResponseRestDTO,
    RegisterWalletUnitRequestRestDTO, RegisterWalletUnitResponseRestDTO,
    WalletProviderMetadataResponseRestDTO, WalletUnitActivationRequestRestDTO,
};
use crate::router::AppState;

#[endpoint(
    permissions = [],
    post,
    path = "/ssi/wallet-unit/v1",
    request_body = RegisterWalletUnitRequestRestDTO,
    tag = "ssi",
    summary = "Register wallet unit",
    description = indoc::formatdoc! {"
        Register new wallet unit.
    "},
)]
#[deprecated = "Deprecated in favor of POST /ssi/instance/v1"]
pub(crate) async fn register_wallet_unit(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<RegisterWalletUnitRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<RegisterWalletUnitResponseRestDTO> {
    let result = state
        .core
        .managed_instance_service
        .register_instance(request.into())
        .await;
    CreatedOrErrorResponse::from_result(result, state, "registering wallet unit")
}

#[endpoint(
    permissions = [],
    post,
    path = "/ssi/wallet-unit/v1/{id}/activate",
    params(
        ("id" = ManagedInstanceId, Path, description = "Wallet unit id")
    ),
    request_body = WalletUnitActivationRequestRestDTO,
    tag = "ssi",
    summary = "Activates wallet unit",
    description = indoc::formatdoc! {"
        Activates wallet unit.
    "},
)]
#[deprecated = "Deprecated in favor of POST /ssi/instance/v1/{id}/activate"]
pub(crate) async fn activate_wallet_unit(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<ManagedInstanceId>, ErrorResponseRestDTO>,
    WithRejection(Json(request), _): WithRejection<
        Json<WalletUnitActivationRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .managed_instance_service
        .activate_instance(id, request.into())
        .await;
    EmptyOrErrorResponse::from_result(result.map(|_| ()), state, "activating wallet unit")
}

#[endpoint(
    permissions = [],
    post,
    path = "/ssi/wallet-unit/v1/{id}/issue-attestation",
    params(
        ("id" = ManagedInstanceId, Path, description = "Wallet unit id")
    ),
    request_body = IssueWalletUnitAttestationRequestRestDTO,
    security(
        ("wallet-unit" = [])
    ),
    tag = "ssi",
    summary = "Issues wallet attestations",
    description = indoc::formatdoc! {"
        Issue wallet app and wallet unit attestations.
    "},
)]
#[deprecated = "Deprecated in favor of POST /ssi/instance/v1/{id}/issue-attestation"]
pub(crate) async fn issue_wallet_unit_attestation(
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
    OkOrErrorResponse::from_result(result, state, "issuing wallet attestation")
}

#[endpoint(
    permissions = [],
    get,
    path = "/ssi/wallet-provider/v1/{walletProvider}",
    params(
        ("walletProvider" = String, Path, description = "Wallet Provider ID")
    ),
    tag = "ssi",
    summary = "Retrieve Wallet Provider info",
    description = indoc::formatdoc! {"
        Returns configuration and policies from the Wallet Provider.
    "},
)]
pub(crate) async fn get_wallet_provider_metadata(
    state: State<AppState>,
    WithRejection(Path(wallet_provider), _): WithRejection<Path<String>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<WalletProviderMetadataResponseRestDTO> {
    let result = state
        .core
        .managed_instance_service
        .get_wallet_provider_metadata(wallet_provider)
        .await;
    OkOrErrorResponse::from_result(result, state, "getting wallet provider metadata")
}

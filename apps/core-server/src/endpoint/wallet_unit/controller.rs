use axum::Json;
use axum::extract::{Path, Query, State};
use axum_extra::extract::WithRejection;
use proc_macros::require_permissions;
use shared_types::{OrganisationId, WalletUnitId};

use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::dto::response::{EmptyOrErrorResponse, OkOrErrorResponse};
use crate::endpoint::wallet_unit::dto::{
    GetWalletUnitsResponseRestDTO, HolderAttestationsQueryParams,
    HolderRefreshWalletUnitRequestRestDTO, HolderRegisterWalletUnitRequestRestDTO,
    HolderRegisterWalletUnitResponseRestDTO, HolderWalletUnitAttestationResponseRestDTO,
    ListWalletUnitsQuery, WalletUnitResponseRestDTO,
};
use crate::extractor::Qs;
use crate::permissions::Permission;
use crate::router::AppState;

#[utoipa::path(
    get,
    path = "/api/wallet-unit/v1",
    params(ListWalletUnitsQuery),
    responses(OkOrErrorResponse<GetWalletUnitsResponseRestDTO>),
    tag = "wallet_unit",
    security(
        ("bearer" = [])
    ),
    summary = "List wallet units",
    description = indoc::formatdoc! {"
    Returns a list of wallet units.
"},
)]
#[require_permissions(Permission::WalletUnitList)]
pub(crate) async fn get_wallet_unit_list(
    state: State<AppState>,
    WithRejection(Qs(query), _): WithRejection<Qs<ListWalletUnitsQuery>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetWalletUnitsResponseRestDTO> {
    let result = async {
        let organisation_id = fallback_organisation_id_from_session(query.filter.organisation_id)?;
        state
            .core
            .wallet_unit_service
            .get_wallet_unit_list(&organisation_id, query.try_into()?)
            .await
    }
    .await;
    OkOrErrorResponse::from_result(result, state, "getting wallet unit list")
}

#[utoipa::path(
    get,
    path = "/api/wallet-unit/v1/{id}",
    params(
        ("id" = WalletUnitId, Path, description = "Wallet unit id")
    ),
    responses(OkOrErrorResponse<WalletUnitResponseRestDTO>),
    tag = "wallet_unit",
    security(
        ("bearer" = [])
    ),
    summary = "Retrieve a wallet unit",
    description = "Returns details on a given wallet unit.",
)]
#[require_permissions(Permission::WalletUnitDetail)]
pub(crate) async fn get_wallet_unit_details(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<WalletUnitId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<WalletUnitResponseRestDTO> {
    let result = state.core.wallet_unit_service.get_wallet_unit(&id).await;
    OkOrErrorResponse::from_result(result, state, "fetching wallet unit")
}

#[utoipa::path(
    post,
    path = "/api/wallet-unit/v1/{id}/revoke",
    params(
        ("id" = WalletUnitId, Path, description = "Wallet unit id")
    ),
    responses(OkOrErrorResponse<WalletUnitResponseRestDTO>),
    tag = "wallet_unit",
    security(
        ("bearer" = [])
    ),
    summary = "Revokes a wallet unit",
    description = "Revokes a given wallet unit.",
)]
#[require_permissions(Permission::WalletUnitRevoke)]
pub(crate) async fn revoke_wallet_unit(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<WalletUnitId>, ErrorResponseRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .ssi_wallet_provider_service
        .revoke_wallet_unit(&id)
        .await;
    EmptyOrErrorResponse::from_result(result, state, "revoking wallet unit")
}

#[utoipa::path(
    delete,
    path = "/api/wallet-unit/v1/{id}",
    params(
        ("id" = WalletUnitId, Path, description = "Wallet unit id")
    ),
    responses(OkOrErrorResponse<WalletUnitResponseRestDTO>),
    tag = "wallet_unit",
    security(
        ("bearer" = [])
    ),
    summary = "Permanently removes a wallet unit",
    description = "Permanently removes  a given wallet unit.",
)]
#[require_permissions(Permission::WalletUnitDelete)]
pub(crate) async fn remove_wallet_unit(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<WalletUnitId>, ErrorResponseRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .ssi_wallet_provider_service
        .delete_wallet_unit(&id)
        .await;
    EmptyOrErrorResponse::from_result(result, state, "deleting wallet unit")
}

#[utoipa::path(
    post,
    path = "/api/wallet-unit/v1/holder-register",
    request_body = HolderRegisterWalletUnitRequestRestDTO,
    responses(OkOrErrorResponse<HolderRegisterWalletUnitResponseRestDTO>),
    tag = "wallet_unit",
    security(
        ("bearer" = [])
    ),
    summary = "Register wallet unit and fetch attestation.",
    description = indoc::formatdoc! {"
        Register wallet unit and fetch attestation.
    "},
)]
#[require_permissions(Permission::WalletAttestationCreate)]
pub(crate) async fn wallet_unit_holder_register(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<HolderRegisterWalletUnitRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<HolderRegisterWalletUnitResponseRestDTO> {
    let result = state
        .core
        .wallet_unit_service
        .holder_register(request.into())
        .await;
    OkOrErrorResponse::from_result(result, state, "register wallet unit")
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
#[require_permissions(Permission::WalletAttestationEdit)]
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
        ("organisationId" = OrganisationId, Query, description = "Organization id")
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
#[require_permissions(Permission::WalletAttestationDetail)]
pub(crate) async fn wallet_unit_holder_attestation(
    state: State<AppState>,
    WithRejection(Query(query_params), _): WithRejection<
        Query<HolderAttestationsQueryParams>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<HolderWalletUnitAttestationResponseRestDTO> {
    let result = state
        .core
        .wallet_unit_service
        .holder_attestation(query_params.organisation_id)
        .await;
    OkOrErrorResponse::from_result(result, state, "get wallet unit attestation")
}

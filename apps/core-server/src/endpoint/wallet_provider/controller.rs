use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use proc_macros::require_permissions;
use shared_types::WalletUnitId;

use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::dto::response::{EmptyOrErrorResponse, OkOrErrorResponse};
use crate::endpoint::wallet_provider::dto::{
    GetWalletUnitsResponseRestDTO, ListWalletUnitsQuery, WalletUnitResponseRestDTO,
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
            .wallet_provider_service
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
    let result = state
        .core
        .wallet_provider_service
        .get_wallet_unit(&id)
        .await;
    OkOrErrorResponse::from_result(result, state, "fetching wallet unit")
}

#[utoipa::path(
    post,
    path = "/api/wallet-unit/v1/{id}/revoke",
    params(
        ("id" = WalletUnitId, Path, description = "Wallet unit id")
    ),
    responses(EmptyOrErrorResponse),
    tag = "wallet_unit",
    security(
        ("bearer" = [])
    ),
    summary = "Revoke a wallet unit",
    description = "Revokes a given wallet unit.",
)]
#[require_permissions(Permission::WalletUnitRevoke)]
pub(crate) async fn revoke_wallet_unit(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<WalletUnitId>, ErrorResponseRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .wallet_provider_service
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
    responses(EmptyOrErrorResponse),
    tag = "wallet_unit",
    security(
        ("bearer" = [])
    ),
    summary = "Delete a wallet unit",
    description = "Permanently deletes a given wallet unit from the database, including history entries.",
)]
#[require_permissions(Permission::WalletUnitDelete)]
pub(crate) async fn remove_wallet_unit(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<WalletUnitId>, ErrorResponseRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .wallet_provider_service
        .delete_wallet_unit(&id)
        .await;
    EmptyOrErrorResponse::from_result(result, state, "deleting wallet unit")
}

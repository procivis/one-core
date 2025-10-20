use axum::Json;
use axum::extract::{Query, State};
use axum_extra::extract::WithRejection;
use proc_macros::require_permissions;
use shared_types::OrganisationId;

use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::dto::response::{EmptyOrErrorResponse, OkOrErrorResponse};
use crate::endpoint::wallet_unit::dto::{
    HolderAttestationsQueryParams, HolderRefreshWalletUnitRequestRestDTO,
    HolderRegisterWalletUnitRequestRestDTO, HolderRegisterWalletUnitResponseRestDTO,
    HolderWalletUnitAttestationResponseRestDTO,
};
use crate::permissions::Permission;
use crate::router::AppState;

#[utoipa::path(
    post,
    path = "/api/wallet-unit/v1/holder-register",
    request_body = HolderRegisterWalletUnitRequestRestDTO,
    responses(OkOrErrorResponse<HolderRegisterWalletUnitResponseRestDTO>),
    tag = "wallet_unit",
    security(
        ("bearer" = [])
    ),
    summary = "Register wallet unit",
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
    let result = async {
        state
            .core
            .wallet_unit_service
            .holder_register(request.try_into()?)
            .await
    }
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
    summary = "Refresh wallet unit attestation",
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
    let result = async {
        state
            .core
            .wallet_unit_service
            .holder_refresh(request.try_into()?)
            .await
    }
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
    summary = "Retrieve wallet unit attestation",
    description = indoc::formatdoc! {"
        Retrieve wallet unit attestation.
    "},
)]
#[require_permissions(Permission::WalletAttestationDetail)]
pub(crate) async fn wallet_unit_holder_attestation(
    state: State<AppState>,
    WithRejection(Query(query), _): WithRejection<
        Query<HolderAttestationsQueryParams>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<HolderWalletUnitAttestationResponseRestDTO> {
    let result = async {
        state
            .core
            .wallet_unit_service
            .holder_attestation(fallback_organisation_id_from_session(
                query.organisation_id,
            )?)
            .await
    }
    .await;
    OkOrErrorResponse::from_result(result, state, "get wallet unit attestation")
}

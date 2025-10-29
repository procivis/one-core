use axum::Json;
use axum::extract::State;
use axum_extra::extract::WithRejection;
use proc_macros::require_permissions;

use crate::dto::common::EntityResponseRestDTO;
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::CreatedOrErrorResponse;
use crate::endpoint::holder_wallet_unit::dto::HolderRegisterWalletUnitRequestRestDTO;
use crate::permissions::Permission;
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
    summary = "Register wallet unit",
    description = indoc::formatdoc! {"
        Register wallet unit with the given wallet provider.
    "},
)]
#[require_permissions(Permission::WalletAttestationCreate)]
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

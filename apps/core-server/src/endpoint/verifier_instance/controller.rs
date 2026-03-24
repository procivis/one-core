use axum::Json;
use axum::extract::State;
use axum_extra::extract::WithRejection;
use proc_macros::endpoint;
use shared_types::Permission;

use super::dto::{RegisterVerifierInstanceRequestRestDTO, RegisterVerifierInstanceResponseRestDTO};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::CreatedOrErrorResponse;
use crate::router::AppState;

#[endpoint(
    permissions = [Permission::VerifierInstanceRegister],
    post,
    path = "/api/verifier-instance/v1",
    request_body = RegisterVerifierInstanceRequestRestDTO,
    responses(CreatedOrErrorResponse<RegisterVerifierInstanceResponseRestDTO>),
    tag = "verifier_instance",
    security(
        ("bearer" = [])
    ),
    summary = "Register verifier instance",
)]
pub(crate) async fn register_verifier_instance(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<RegisterVerifierInstanceRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<RegisterVerifierInstanceResponseRestDTO> {
    let result = state
        .core
        .verifier_instance_service
        .register_verifier_instance(request.into())
        .await;
    CreatedOrErrorResponse::from_result(result, state, "register verifier instance")
}

use axum::Json;
use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use proc_macros::endpoint;
use shared_types::{Permission, VerifierInstanceId};

use super::dto::{RegisterVerifierInstanceRequestRestDTO, RegisterVerifierInstanceResponseRestDTO};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{CreatedOrErrorResponse, OkOrErrorResponse};
use crate::endpoint::holder_wallet_unit::dto::TrustCollectionsDetailRestDTO;
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

#[endpoint(
    permissions = [Permission::VerifierInstanceDetail],
    get,
    path = "/api/verifier-instance/v1/{id}/trust-collections",
    responses(OkOrErrorResponse<TrustCollectionsDetailRestDTO>),
    params(
        ("id" = VerifierInstanceId, Path, description = "Verifier instance ID")
    ),
    tag = "verifier_instance",
    security(
        ("bearer" = [])
    ),
    summary = "Get trust collections",
    description = "Get trust collections associated with the given verifier instance",
)]
pub(crate) async fn get_verifier_instance_trust_collections(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<VerifierInstanceId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<TrustCollectionsDetailRestDTO> {
    let result = state
        .core
        .verifier_instance_service
        .get_trust_collections(id)
        .await;

    OkOrErrorResponse::from_result(result, state, "getting verifier instance trust collections")
}

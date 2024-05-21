use axum::extract::State;
use axum::Json;
use axum_extra::extract::WithRejection;

use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::EmptyOrErrorResponse;

use crate::router::AppState;

use super::dto::CreateTrustEntityRequestRestDTO;

#[utoipa::path(
    post,
    path = "/api/trust-entity/v1",
    request_body = CreateTrustEntityRequestRestDTO,
    responses(EmptyOrErrorResponse),
    tag = "trust-entity",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn create_trust_entity(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<CreateTrustEntityRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .trust_entity_service
        .create_trust_entity(request.into())
        .await;
    EmptyOrErrorResponse::from_result(result, state, "creating trust entity")
}

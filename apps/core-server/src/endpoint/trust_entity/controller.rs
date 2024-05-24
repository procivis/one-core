use axum::extract::State;
use axum::Json;
use axum_extra::extract::WithRejection;

use super::dto::CreateTrustEntityRequestRestDTO;
use crate::dto::common::EntityResponseRestDTO;
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::CreatedOrErrorResponse;
use crate::router::AppState;

#[utoipa::path(
    post,
    path = "/api/trust-entity/v1",
    request_body = CreateTrustEntityRequestRestDTO,
    responses(CreatedOrErrorResponse<EntityResponseRestDTO>),
    tag = "trust_entity",
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
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let result = state
        .core
        .trust_entity_service
        .create_trust_entity(request.into())
        .await;
    CreatedOrErrorResponse::from_result(result, state, "creating trust entity")
}

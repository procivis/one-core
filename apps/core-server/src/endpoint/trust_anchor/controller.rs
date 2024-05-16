use axum::extract::State;
use axum::Json;
use axum_extra::extract::WithRejection;

use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::EmptyOrErrorResponse;

use crate::router::AppState;

use super::dto::CreateTrustAnchorRequestRestDTO;

#[utoipa::path(
    post,
    path = "/api/trust-anchor/v1",
    request_body = CreateTrustAnchorRequestRestDTO,
    responses(EmptyOrErrorResponse),
    tag = "trust-anchor",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn create_trust_anchor(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<CreateTrustAnchorRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .trust_anchor_service
        .create_trust_anchor(request.into())
        .await;
    EmptyOrErrorResponse::from_result(result, state, "creating trust anchor")
}

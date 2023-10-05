use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use one_core::service::error::ServiceError;

use crate::dto::common::EntityResponseRestDTO;
use crate::endpoint::key::dto::KeyRequestRestDTO;
use crate::router::AppState;

#[utoipa::path(
    post,
    path = "/api/key/v1",
    request_body = KeyRequestRestDTO,
    responses(
        (status = 201, description = "OK", body = EntityResponseRestDTO),
        (status = 400, description = "Invalid params"),
        (status = 422, description = "Unsupported key/storage params"),
    ),
    tag = "interaction",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn post_key(
    state: State<AppState>,
    Json(request): Json<KeyRequestRestDTO>,
) -> Response {
    let result = state.core.key_service.generate_key(request.into()).await;

    match result {
        Ok(value) => (StatusCode::OK, Json(EntityResponseRestDTO { id: value })).into_response(),
        Err(ServiceError::ConfigValidationError(error)) => {
            tracing::error!("Config validation error: {:?}", error);
            StatusCode::UNPROCESSABLE_ENTITY.into_response()
        }
        Err(ServiceError::IncorrectParameters) => {
            tracing::error!("Invalid parameters: {:?}", result);
            StatusCode::BAD_REQUEST.into_response()
        }
        Err(error) => {
            tracing::error!("Unknown error: {:?}", error);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

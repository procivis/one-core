use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use one_core::service::error::ServiceError;
use uuid::Uuid;

use crate::dto::common::{EntityResponseRestDTO, GetKeyListResponseRestDTO};
use crate::endpoint::key::dto::{KeyRequestRestDTO, KeyResponseRestDTO};
use crate::extractor::Qs;
use crate::router::AppState;

#[utoipa::path(
    get,
    path = "/api/key/v1/{id}",
    responses(
        (status = 200, description = "OK", body = KeyResponseRestDTO),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Key not found"),
    ),
    params(
        ("id" = Uuid, Path, description = "Key id")
    ),
    tag = "key",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_key(state: State<AppState>, Path(id): Path<Uuid>) -> Response {
    let result = state.core.key_service.get_key(&id).await;

    match result {
        Ok(value) => (StatusCode::OK, Json(KeyResponseRestDTO::from(value))).into_response(),
        Err(error) => match error {
            ServiceError::NotFound => StatusCode::NOT_FOUND.into_response(),
            _ => {
                tracing::error!("Error while getting key: {:?}", error);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
    }
}

use super::dto::GetKeyQuery;

#[utoipa::path(
    post,
    path = "/api/key/v1",
    request_body = KeyRequestRestDTO,
    responses(
        (status = 201, description = "OK", body = EntityResponseRestDTO),
        (status = 400, description = "Invalid params"),
        (status = 422, description = "Unsupported key/storage params"),
    ),
    tag = "key",
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

#[utoipa::path(
    get,
    path = "/api/key/v1",
    responses(
        (status = 200, description = "OK", body = GetKeyListResponseRestDTO),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Server error"),
    ),
    params(
        GetKeyQuery
    ),
    tag = "key",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_key_list(state: State<AppState>, Qs(query): Qs<GetKeyQuery>) -> Response {
    let result = state.core.key_service.get_key_list(query.into()).await;

    match result {
        Err(error) => {
            tracing::error!("Error while getting keys: {:?}", error);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Ok(value) => (StatusCode::OK, Json(GetKeyListResponseRestDTO::from(value))).into_response(),
    }
}

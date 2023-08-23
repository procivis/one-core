use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};
use one_core::repository::error::DataLayerError;
use uuid::Uuid;

use crate::data_model::EntityShareResponseDTO;
use crate::AppState;

#[utoipa::path(
    post,
    path = "/api/credential/v1/{id}/share",
    responses(
        (status = 200, description = "Created", body = EntityShareResponseDTO),
        (status = 400, description = "Credential has been shared already"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Credential schema or DID not found"),
    ),
    params(
        ("id" = Uuid, Path, description = "Credential id")
    ),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn share_credential(state: State<AppState>, Path(id): Path<Uuid>) -> Response {
    let result = state
        .core
        .data_layer
        .share_credential(&id.to_string())
        .await;

    match result {
        Ok(value) => (StatusCode::OK, Json(EntityShareResponseDTO::from(value))).into_response(),
        Err(error) => match error {
            DataLayerError::RecordNotFound => StatusCode::NOT_FOUND.into_response(),
            DataLayerError::AlreadyExists => StatusCode::BAD_REQUEST.into_response(),
            other => {
                tracing::error!("Error while getting credential: {other:?}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
    }
}

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};

use one_core::data_layer::DataLayerError;

use crate::data_model::{CredentialRequestDTO, EntityResponseDTO};
use crate::AppState;

#[utoipa::path(
    post,
    path = "/api/credential/v1",
    request_body = CredentialRequestDTO,
    responses(
        (status = 200, description = "Created", body = EntityResponseDTO),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Credential schema or DID not found"),
    ),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn post_credential(
    state: State<AppState>,
    Json(request): Json<CredentialRequestDTO>,
) -> Response {
    let result = state
        .core
        .data_layer
        .create_credential(request.into())
        .await;

    match result {
        Ok(value) => (StatusCode::OK, Json(EntityResponseDTO::from(value))).into_response(),
        Err(error) => match error {
            DataLayerError::RecordNotFound => StatusCode::NOT_FOUND.into_response(),
            _ => {
                tracing::error!("Error while getting credential");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
    }
}

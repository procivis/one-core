use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};

use one_core::data_layer::DataLayerError;

use uuid::Uuid;

use crate::data_model::GetDidDetailsResponseDTO;
use crate::AppState;
#[utoipa::path(
    get,
    path = "/api/did/v1/{id}",
    responses(
        (status = 200, description = "OK", body = GetDidDetailsResponseDTO),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "DID not found"),
        (status = 500, description = "Server error"),
    ),
    params(
        ("id" = Uuid, Path, description = "DID id")
    ),
    tag = "did_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_did_details(state: State<AppState>, Path(id): Path<Uuid>) -> Response {
    let result = state.core.data_layer.get_did_details(&id.to_string()).await;

    match result {
        Err(error) => match error {
            DataLayerError::RecordNotFound => (StatusCode::NOT_FOUND).into_response(),
            _ => {
                tracing::error!("Error while getting did details: {:?}", error);
                (StatusCode::INTERNAL_SERVER_ERROR).into_response()
            }
        },
        Ok(value) => (StatusCode::OK, Json(GetDidDetailsResponseDTO::from(value))).into_response(),
    }
}

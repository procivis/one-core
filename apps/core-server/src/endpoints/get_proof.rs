use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};

use uuid::Uuid;

use one_core::data_layer::DataLayerError;

use crate::data_model::ProofDetailsResponseDTO;
use crate::AppState;

#[utoipa::path(
    get,
    path = "/api/proof-request/v1/{id}",
    responses(
        (status = 200, description = "OK", body = ProofDetailsResponseDTO),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Credential not found"),
    ),
    params(
        ("id" = Uuid, Path, description = "Proof id")
    ),
    tag = "proof_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_proof_details(state: State<AppState>, Path(id): Path<Uuid>) -> Response {
    let result = state
        .core
        .data_layer
        .get_proof_details(&id.to_string())
        .await;

    match result {
        Ok(value) => (StatusCode::OK, Json(ProofDetailsResponseDTO::from(value))).into_response(),
        Err(error) => match error {
            DataLayerError::RecordNotFound => StatusCode::NOT_FOUND.into_response(),
            _ => {
                tracing::error!("Error while getting proof {error}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
    }
}
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};

use one_core::repository::error::DataLayerError;

use validator::Validate;

use crate::data_model::{CreateProofRequestDTO, CreateProofResponseDTO};
use crate::AppState;

#[utoipa::path(
    post,
    path = "/api/proof-request/v1",
    request_body = CreateProofRequestDTO,
    responses(
        (status = 200, description = "Created", body = CreateProofResponseDTO),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "proof_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn post_proof(
    state: State<AppState>,
    Json(request): Json<CreateProofRequestDTO>,
) -> Response {
    if let Err(e) = request.validate() {
        tracing::error!("Request validation failure: {}", e.to_string());
        return (StatusCode::BAD_REQUEST, "Validation failed").into_response();
    }

    let result = state.core.data_layer.create_proof(request.into()).await;

    match result {
        Err(DataLayerError::RecordNotFound) | Err(DataLayerError::IncorrectParameters) => {
            tracing::error!("Missing Proof schema or Verifier DID");
            StatusCode::NOT_FOUND.into_response()
        }
        Err(DataLayerError::GeneralRuntimeError(e)) => {
            tracing::error!("Database runtime error: {:?}", e);
            StatusCode::BAD_REQUEST.into_response()
        }
        Err(e) => {
            tracing::error!("Error while getting credential: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Ok(value) => (
            StatusCode::CREATED,
            Json(CreateProofResponseDTO { id: value.id }),
        )
            .into_response(),
    }
}

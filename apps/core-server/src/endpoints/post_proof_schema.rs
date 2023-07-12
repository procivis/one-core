use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};

use one_core::data_layer::DataLayerError;

use validator::Validate;

use crate::data_model::{CreateProofSchemaRequestDTO, CreateProofSchemaResponseDTO};
use crate::AppState;

#[utoipa::path(
    post,
    path = "/api/proof-schema/v1",
    request_body = CreateProofSchemaRequestDTO,
    responses(
        (status = 201, description = "Created"),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "proof_schema_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn post_proof_schema(
    state: State<AppState>,
    Json(request): Json<CreateProofSchemaRequestDTO>,
) -> Response {
    if let Err(e) = request.validate() {
        tracing::error!("Request validation failure: {}", e.to_string());
        return StatusCode::BAD_REQUEST.into_response();
    }

    let result = state
        .core
        .data_layer
        .create_proof_schema(request.into())
        .await;

    match result {
        Err(DataLayerError::AlreadyExists) => {
            tracing::error!("Name duplicated in the organisation");
            StatusCode::CONFLICT.into_response()
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
            Json(CreateProofSchemaResponseDTO::from(value)),
        )
            .into_response(),
    }
}

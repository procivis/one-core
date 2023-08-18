use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use one_core::data_layer::DataLayerError;

use validator::Validate;

use crate::data_model::{CreateCredentialSchemaRequestDTO, CreateCredentialSchemaResponseDTO};
use crate::AppState;

#[utoipa::path(
    post,
    path = "/api/credential-schema/v1",
    request_body = CreateCredentialSchemaRequestDTO,
    responses(
        (status = 201, description = "Created", body = CreateCredentialSchemaResponseDTO),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Duplicated name"),
    ),
    tag = "credential_schema_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn post_credential_schema(
    state: State<AppState>,
    Json(request): Json<CreateCredentialSchemaRequestDTO>,
) -> Response {
    if let Err(e) = request.validate() {
        tracing::error!("Request validation failure: {}", e.to_string());
        return StatusCode::BAD_REQUEST.into_response();
    }

    let result = state
        .core
        .data_layer
        .create_credential_schema(request.into(), &state.core.config.datatype)
        .await;

    match result {
        Err(DataLayerError::AlreadyExists) => {
            tracing::error!("Credential schema already exists");
            StatusCode::CONFLICT.into_response()
        }
        Err(DataLayerError::DatatypeValidationError(error)) => {
            tracing::error!("Datatype validation error: {:?}", error);
            StatusCode::BAD_REQUEST.into_response()
        }
        Err(error) => {
            tracing::error!("Error while inserting credential: {:?}", error);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Ok(value) => (
            StatusCode::CREATED,
            Json(CreateCredentialSchemaResponseDTO::from(value)),
        )
            .into_response(),
    }
}

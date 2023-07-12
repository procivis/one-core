use axum::extract::State;

use axum::{http::StatusCode, Json};

use one_core::data_layer::DataLayerError;

use validator::Validate;

use crate::data_model::CreateCredentialSchemaRequestDTO;
use crate::AppState;

#[utoipa::path(
    post,
    path = "/api/credential-schema/v1",
    request_body = CreateCredentialSchemaRequestDTO,
    responses(
        (status = 204, description = "Created"),
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
) -> StatusCode {
    if let Err(e) = request.validate() {
        tracing::error!("Request validation failure: {}", e.to_string());
        return StatusCode::BAD_REQUEST;
    }

    let result = state
        .core
        .data_layer
        .create_credential_schema(request.into())
        .await;

    if let Err(error) = result {
        tracing::error!("Error while inserting credential: {:?}", error);
        match error {
            DataLayerError::AlreadyExists => return StatusCode::CONFLICT,
            _ => return StatusCode::INTERNAL_SERVER_ERROR,
        };
    }

    StatusCode::NO_CONTENT
}

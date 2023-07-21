use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};

use one_core::data_layer::DataLayerError;

use uuid::Uuid;

use crate::data_model::{
    CredentialSchemaResponseDTO, GetCredentialClaimSchemaResponseDTO, GetCredentialSchemaQuery,
};
use crate::AppState;

#[utoipa::path(
    get,
    path = "/api/credential-schema/v1",
    responses(
        (status = 200, description = "OK", body = GetCredentialClaimSchemaResponseDTO),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Server error"),
    ),
    params(
        GetCredentialSchemaQuery
    ),
    tag = "credential_schema_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_credential_schema(
    state: State<AppState>,
    Query(query): Query<GetCredentialSchemaQuery>,
) -> Response {
    let result = state
        .core
        .data_layer
        .get_credential_schemas(query.into())
        .await;

    match result {
        Err(error) => {
            tracing::error!("Error while getting credential: {:?}", error);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Ok(value) => (
            StatusCode::OK,
            Json(GetCredentialClaimSchemaResponseDTO::from(value)),
        )
            .into_response(),
    }
}

#[utoipa::path(
    get,
    path = "/api/credential-schema/v1/{id}",
    responses(
        (status = 200, description = "OK", body = CredentialSchemaResponseDTO),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Schema not found"),
        (status = 500, description = "Server error"),
    ),
    params(
        ("id" = Uuid, Path, description = "Schema id")
    ),
    tag = "credential_schema_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_credential_schema_details(
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> Response {
    let result = state
        .core
        .data_layer
        .get_credential_schema_details(&id.to_string())
        .await;

    match result {
        Err(error) => match error {
            DataLayerError::RecordNotFound => StatusCode::NOT_FOUND.into_response(),
            _ => {
                tracing::error!("Error while getting credential");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
        Ok(value) => (
            StatusCode::OK,
            Json(CredentialSchemaResponseDTO::from(value)),
        )
            .into_response(),
    }
}

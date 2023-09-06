use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};
use uuid::Uuid;
use validator::Validate;

use one_core::service::error::ServiceError;

use crate::dto::common::GetCredentialSchemaResponseDTO;
use crate::endpoint::credential_schema::dto::{
    CreateCredentialSchemaRequestRestDTO, CreateCredentialSchemaResponseRestDTO,
};
use crate::AppState;

use super::dto::{CredentialSchemaResponseRestDTO, GetCredentialSchemaQuery};

#[utoipa::path(
    delete,
    path = "/api/credential-schema/v1/{id}",
    responses(
        (status = 204, description = "Deleted"),
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
pub(crate) async fn delete_credential_schema(
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> StatusCode {
    let result = state
        .core
        .credential_schema_service
        .delete_credential_schema(&id)
        .await;

    if let Err(error) = result {
        return match error {
            ServiceError::NotFound => StatusCode::NOT_FOUND,
            _ => {
                tracing::error!("Error while deleting credential schema: {:?}", error);
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
    }

    StatusCode::NO_CONTENT
}

#[utoipa::path(
    get,
    path = "/api/credential-schema/v1/{id}",
    responses(
        (status = 200, description = "OK", body = CredentialSchemaResponseRestDTO),
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
pub(crate) async fn get_credential_schema(
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> Response {
    let result = state
        .core
        .credential_schema_service
        .get_credential_schema(&id)
        .await;

    match result {
        Err(error) => match error {
            ServiceError::NotFound => (StatusCode::NOT_FOUND).into_response(),
            _ => {
                tracing::error!("Error while getting credential schema: {:?}", error);
                (StatusCode::INTERNAL_SERVER_ERROR).into_response()
            }
        },
        Ok(value) => (
            StatusCode::OK,
            Json(CredentialSchemaResponseRestDTO::from(value)),
        )
            .into_response(),
    }
}

#[utoipa::path(
    get,
    path = "/api/credential-schema/v1",
    responses(
        (status = 200, description = "OK", body = GetCredentialSchemaResponseDTO),
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
pub(crate) async fn get_credential_schema_list(
    state: State<AppState>,
    Query(query): Query<GetCredentialSchemaQuery>,
) -> Response {
    let result = state
        .core
        .credential_schema_service
        .get_credential_schema_list(query.into())
        .await;

    match result {
        Err(error) => {
            tracing::error!("Error while getting credential schemas: {:?}", error);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Ok(value) => (
            StatusCode::OK,
            Json(GetCredentialSchemaResponseDTO::from(value)),
        )
            .into_response(),
    }
}

#[utoipa::path(
    post,
    path = "/api/credential-schema/v1",
    request_body = CreateCredentialSchemaRequestRestDTO,
    responses(
        (status = 201, description = "Created", body = CreateCredentialSchemaResponseRestDTO),
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
    Json(request): Json<CreateCredentialSchemaRequestRestDTO>,
) -> Response {
    if let Err(e) = request.validate() {
        tracing::error!("Request validation failure: {}", e.to_string());
        return StatusCode::BAD_REQUEST.into_response();
    }

    let result = state
        .core
        .credential_schema_service
        .create_credential_schema(request.into())
        .await;

    match result {
        Err(ServiceError::AlreadyExists) => {
            tracing::error!("Credential schema already exists");
            StatusCode::CONFLICT.into_response()
        }
        Err(ServiceError::ConfigValidationError(error)) => {
            tracing::error!("Config validation error: {:?}", error);
            StatusCode::BAD_REQUEST.into_response()
        }
        Err(error) => {
            tracing::error!("Error while inserting credential schema: {:?}", error);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Ok(value) => (
            StatusCode::CREATED,
            Json(CreateCredentialSchemaResponseRestDTO::from(value)),
        )
            .into_response(),
    }
}

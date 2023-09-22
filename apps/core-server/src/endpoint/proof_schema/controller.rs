use super::dto::{
    CreateProofSchemaRequestRestDTO, CreateProofSchemaResponseRestDTO, GetProofSchemaQuery,
    GetProofSchemaResponseRestDTO,
};
use crate::dto::common::GetProofSchemaListResponseRestDTO;
use crate::extractor::Qs;
use crate::AppState;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};
use one_core::service::error::ServiceError;
use uuid::Uuid;
use validator::Validate;

#[utoipa::path(
    post,
    path = "/api/proof-schema/v1",
    request_body = CreateProofSchemaRequestRestDTO,
    responses(
        (status = 201, description = "Created", body = CreateProofSchemaResponseRestDTO),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Already exists"),
        (status = 500, description = "Internal server error")
    ),
    tag = "proof_schema_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn post_proof_schema(
    state: State<AppState>,
    Json(request): Json<CreateProofSchemaRequestRestDTO>,
) -> Response {
    if let Err(e) = request.validate() {
        tracing::error!("Request validation failure: {}", e.to_string());
        return StatusCode::BAD_REQUEST.into_response();
    }

    let result = state
        .core
        .proof_schema_service
        .create_proof_schema(request.into())
        .await;

    match result {
        Err(ServiceError::AlreadyExists) => {
            tracing::error!("Name duplicated in the organisation");
            StatusCode::CONFLICT.into_response()
        }
        Err(ServiceError::IncorrectParameters) => {
            tracing::error!("Invalid request");
            StatusCode::BAD_REQUEST.into_response()
        }
        Err(e) => {
            tracing::error!("Error while creating proof schema: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Ok(value) => (
            StatusCode::CREATED,
            Json(CreateProofSchemaResponseRestDTO { id: value }),
        )
            .into_response(),
    }
}

#[utoipa::path(
    get,
    path = "/api/proof-schema/v1",
    responses(
        (status = 200, description = "OK", body = GetProofSchemaListResponseRestDTO),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Server error"),
    ),
    params(
        GetProofSchemaQuery
    ),
    tag = "proof_schema_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_proof_schemas(
    state: State<AppState>,
    Qs(query): Qs<GetProofSchemaQuery>,
) -> Response {
    let result = state
        .core
        .proof_schema_service
        .get_proof_schema_list(query.into())
        .await;

    match result {
        Err(error) => {
            tracing::error!("Error while getting proof schemas: {:?}", error);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Ok(value) => (
            StatusCode::OK,
            Json(GetProofSchemaListResponseRestDTO::from(value)),
        )
            .into_response(),
    }
}

#[utoipa::path(
    get,
    path = "/api/proof-schema/v1/{id}",
    responses(
        (status = 200, description = "OK", body = GetProofSchemaResponseRestDTO),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Schema not found"),
        (status = 500, description = "Server error"),
    ),
    params(
        ("id" = Uuid, Path, description = "Schema id")
    ),
    tag = "proof_schema_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_proof_schema_detail(
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> Response {
    let result = state.core.proof_schema_service.get_proof_schema(&id).await;

    match result {
        Err(error) => match error {
            ServiceError::NotFound => (StatusCode::NOT_FOUND).into_response(),
            _ => {
                tracing::error!("Error while getting proof schema: {:?}", error);
                (StatusCode::INTERNAL_SERVER_ERROR).into_response()
            }
        },
        Ok(value) => (
            StatusCode::OK,
            Json(GetProofSchemaResponseRestDTO::from(value)),
        )
            .into_response(),
    }
}

#[utoipa::path(
    delete,
    path = "/api/proof-schema/v1/{id}",
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Schema not found"),
        (status = 500, description = "Server error"),
    ),
    params(
        ("id" = Uuid, Path, description = "Schema id")
    ),
    tag = "proof_schema_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn delete_proof_schema(
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> StatusCode {
    let result = state
        .core
        .proof_schema_service
        .delete_proof_schema(&id)
        .await;

    if let Err(error) = result {
        return match error {
            ServiceError::NotFound => StatusCode::NOT_FOUND,
            ServiceError::NotUpdated => StatusCode::NOT_FOUND,
            _ => {
                tracing::error!("Error while deleting proof schema: {:?}", error);
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
    }

    StatusCode::NO_CONTENT
}

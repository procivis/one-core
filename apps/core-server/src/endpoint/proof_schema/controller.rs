use std::sync::Arc;

use super::dto::{
    CreateProofSchemaRequestRestDTO, GetProofSchemaQuery, GetProofSchemaResponseRestDTO,
};
use crate::dto::common::{
    CreatedOrErrorResponse, EntityResponseRestDTO, GetProofSchemaListResponseRestDTO,
};
use crate::extractor::Qs;
use crate::router::AppState;
use crate::ServerConfig;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use axum::{http::StatusCode, Json};
use one_core::service::error::ServiceError;
use uuid::Uuid;

#[utoipa::path(
    post,
    path = "/api/proof-schema/v1",
    request_body = CreateProofSchemaRequestRestDTO,
    responses(CreatedOrErrorResponse<EntityResponseRestDTO>),
    tag = "proof_schema_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn post_proof_schema(
    config: Extension<Arc<ServerConfig>>,
    state: State<AppState>,
    Json(request): Json<CreateProofSchemaRequestRestDTO>,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let result = state
        .core
        .proof_schema_service
        .create_proof_schema(request.into())
        .await;

    match result {
        Ok(id) => CreatedOrErrorResponse::created(EntityResponseRestDTO { id }),
        Err(error) => {
            tracing::error!(%error, "Error while creating proof schema");
            CreatedOrErrorResponse::from_service_error(error, config.hide_error_response_cause)
        }
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

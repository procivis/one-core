use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use axum::{http::StatusCode, Json};

use uuid::Uuid;

use one_core::service::error::{EntityNotFoundError, ServiceError};

use crate::dto::common::{
    CreatedOrErrorResponse, EntityResponseRestDTO, EntityShareResponseRestDTO,
    GetCredentialsResponseDTO, OkOrErrorResponse,
};
use crate::endpoint::credential::dto::{
    CreateCredentialRequestRestDTO, GetCredentialQuery, GetCredentialResponseRestDTO,
};
use crate::extractor::Qs;
use crate::router::AppState;
use crate::ServerConfig;

use super::dto::{
    CredentialRevocationCheckRequestRestDTO, CredentialRevocationCheckResponseRestDTO,
};

#[utoipa::path(
    delete,
    path = "/api/credential/v1/{id}",
    responses(
        (status = 204, description = "No content"),
        (status = 400, description = "Credential in invalid state"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Credential not found"),
    ),
    params(
        ("id" = Uuid, Path, description = "Credential id")
    ),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn delete_credential(state: State<AppState>, Path(id): Path<Uuid>) -> Response {
    let result = state.core.credential_service.delete_credential(&id).await;

    match result {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => match error {
            ServiceError::AlreadyExists => StatusCode::BAD_REQUEST.into_response(),
            ServiceError::NotFound
            | ServiceError::EntityNotFound(EntityNotFoundError::Credential(_)) => {
                StatusCode::NOT_FOUND.into_response()
            }
            _ => {
                tracing::error!("Error while getting credential: {:?}", error);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
    }
}

#[utoipa::path(
    get,
    path = "/api/credential/v1/{id}",
    responses(OkOrErrorResponse<GetCredentialResponseRestDTO>),
    params(
        ("id" = Uuid, Path, description = "Credential id")
    ),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_credential(
    config: Extension<Arc<ServerConfig>>,
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> OkOrErrorResponse<GetCredentialResponseRestDTO> {
    let result = state.core.credential_service.get_credential(&id).await;

    match result {
        Ok(value) => OkOrErrorResponse::ok(value),
        Err(error) => {
            tracing::error!(%error, "Error while getting credential");
            OkOrErrorResponse::from_service_error(error, config.hide_error_response_cause)
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/credential/v1",
    responses(OkOrErrorResponse<GetCredentialsResponseDTO>),
    params(
        GetCredentialQuery
    ),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_credential_list(
    config: Extension<Arc<ServerConfig>>,
    state: State<AppState>,
    Qs(query): Qs<GetCredentialQuery>,
) -> OkOrErrorResponse<GetCredentialsResponseDTO> {
    let result = state
        .core
        .credential_service
        .get_credential_list(query.into())
        .await;

    match result {
        Ok(value) => OkOrErrorResponse::ok(value),
        Err(error) => {
            tracing::error!(%error, "Error while getting credential list");
            OkOrErrorResponse::from_service_error(error, config.hide_error_response_cause)
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/credential/v1",
    request_body = CreateCredentialRequestRestDTO,
    responses(CreatedOrErrorResponse<EntityResponseRestDTO>),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn post_credential(
    config: Extension<Arc<ServerConfig>>,
    state: State<AppState>,
    Json(request): Json<CreateCredentialRequestRestDTO>,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let result = state
        .core
        .credential_service
        .create_credential(request.into())
        .await;

    match result {
        Ok(id) => CreatedOrErrorResponse::created(EntityResponseRestDTO { id }),
        Err(error) => {
            tracing::error!(%error, "Error while creating credential");
            CreatedOrErrorResponse::from_service_error(error, config.hide_error_response_cause)
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/credential/v1/{id}/revoke",
    responses(
        (status = 204, description = "OK"),
        (status = 400, description = "Incorrect state or revocation method"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Credential not found"),
    ),
    params(
        ("id" = Uuid, Path, description = "Credential id")
    ),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn revoke_credential(state: State<AppState>, Path(id): Path<Uuid>) -> Response {
    let result = state.core.credential_service.revoke_credential(&id).await;

    match result {
        Ok(_) => (StatusCode::NO_CONTENT.into_response()).into_response(),
        Err(error) => match error {
            ServiceError::EntityNotFound(_) | ServiceError::NotFound => {
                StatusCode::NOT_FOUND.into_response()
            }
            ServiceError::AlreadyExists => StatusCode::BAD_REQUEST.into_response(),
            ServiceError::ValidationError(message) => {
                (StatusCode::BAD_REQUEST, message).into_response()
            }
            other => {
                tracing::error!("Error while getting credential: {other:?}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
    }
}

#[utoipa::path(
    post,
    path = "/api/credential/v1/{id}/share",
    responses(
        (status = 200, description = "OK", body = EntityShareResponseRestDTO),
        (status = 400, description = "Credential has been shared already"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Credential schema or DID not found"),
    ),
    params(
        ("id" = Uuid, Path, description = "Credential id")
    ),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn share_credential(state: State<AppState>, Path(id): Path<Uuid>) -> Response {
    let result = state.core.credential_service.share_credential(&id).await;

    match result {
        Ok(value) => (
            StatusCode::OK,
            Json(EntityShareResponseRestDTO::from(value)),
        )
            .into_response(),
        Err(error) => match error {
            ServiceError::NotFound => StatusCode::NOT_FOUND.into_response(),
            ServiceError::AlreadyExists | ServiceError::AlreadyShared => {
                StatusCode::BAD_REQUEST.into_response()
            }
            other => {
                tracing::error!("Error while getting credential: {other:?}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
    }
}

#[utoipa::path(
    post,
    path = "/api/credential/v1/revocation-check",
    request_body = CredentialRevocationCheckRequestRestDTO,
    responses(
        (status = 200, description = "OK", body = Vec<CredentialRevocationCheckResponseRestDTO>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Credential not found"),
    ),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn revocation_check(
    state: State<AppState>,
    Json(request): Json<CredentialRevocationCheckRequestRestDTO>,
) -> Response {
    let result = state
        .core
        .credential_service
        .check_revocation(request.credential_ids)
        .await;

    match result {
        Ok(values) => (
            StatusCode::OK,
            Json(
                values
                    .into_iter()
                    .map(Into::<CredentialRevocationCheckResponseRestDTO>::into)
                    .collect::<Vec<_>>(),
            ),
        )
            .into_response(),
        Err(error) => match error {
            ServiceError::NotFound => StatusCode::NOT_FOUND.into_response(),
            other => {
                tracing::error!("Error while checking credentials: {other:?}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
    }
}

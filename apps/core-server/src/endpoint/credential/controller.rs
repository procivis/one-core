use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use axum::{http::StatusCode, Json};

use uuid::Uuid;

use one_core::service::error::ServiceError;

use crate::dto::common::{
    CreatedOrErrorResponse, EmptyOrErrorResponse, EntityResponseRestDTO,
    EntityShareResponseRestDTO, GetCredentialsResponseDTO, OkOrErrorResponse,
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
    responses(EmptyOrErrorResponse),
    params(
        ("id" = Uuid, Path, description = "Credential id")
    ),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn delete_credential(
    config: Extension<Arc<ServerConfig>>,
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> EmptyOrErrorResponse {
    let result = state.core.credential_service.delete_credential(&id).await;

    match result {
        Ok(_) => EmptyOrErrorResponse::NoContent,
        Err(error) => {
            tracing::error!(%error, "Error while deleting credential");
            EmptyOrErrorResponse::from_service_error(error, config.hide_error_response_cause)
        }
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
    responses(EmptyOrErrorResponse),
    params(
        ("id" = Uuid, Path, description = "Credential id")
    ),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn revoke_credential(
    config: Extension<Arc<ServerConfig>>,
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> EmptyOrErrorResponse {
    let result = state.core.credential_service.revoke_credential(&id).await;

    match result {
        Ok(_) => EmptyOrErrorResponse::NoContent,
        Err(error) => {
            tracing::error!(%error, "Error while revoking credential");
            EmptyOrErrorResponse::from_service_error(error, config.hide_error_response_cause)
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/credential/v1/{id}/share",
    responses(OkOrErrorResponse<EntityShareResponseRestDTO>),
    params(
        ("id" = Uuid, Path, description = "Credential id")
    ),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn share_credential(
    config: Extension<Arc<ServerConfig>>,
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> OkOrErrorResponse<EntityShareResponseRestDTO> {
    let result = state.core.credential_service.share_credential(&id).await;

    match result {
        Ok(value) => OkOrErrorResponse::ok(value),
        Err(error) => {
            tracing::error!(%error, "Error while sharing credential");
            OkOrErrorResponse::from_service_error(error, config.hide_error_response_cause)
        }
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

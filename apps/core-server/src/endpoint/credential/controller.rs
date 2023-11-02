use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};

use one_core::common_mapper::vector_into;
use one_core::service::credential::dto::CredentialRevocationCheckResponseDTO;
use uuid::Uuid;

use one_core::service::error::ServiceError;

use crate::dto::common::{
    EntityResponseRestDTO, EntityShareResponseRestDTO, GetCredentialsResponseDTO,
};
use crate::endpoint::credential::dto::{
    CreateCredentialRequestRestDTO, GetCredentialQuery, GetCredentialResponseRestDTO,
};
use crate::extractor::Qs;
use crate::router::AppState;

use super::dto::{
    CredentialRevocationCheckRequestRestDTO, CredentialRevocationCheckResponseRestDTO,
};

#[utoipa::path(
    get,
    path = "/api/credential/v1/{id}",
    responses(
        (status = 200, description = "OK", body = GetCredentialResponseRestDTO),
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
pub(crate) async fn get_credential(state: State<AppState>, Path(id): Path<Uuid>) -> Response {
    let result = state.core.credential_service.get_credential(&id).await;

    match result {
        Ok(value) => (
            StatusCode::OK,
            Json(GetCredentialResponseRestDTO::from(value)),
        )
            .into_response(),
        Err(error) => match error {
            ServiceError::NotFound => StatusCode::NOT_FOUND.into_response(),
            _ => {
                tracing::error!("Error while getting credential: {:?}", error);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
    }
}

#[utoipa::path(
    get,
    path = "/api/credential/v1",
    responses(
        (status = 200, description = "OK", body = GetCredentialsResponseDTO),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Credential not found"),
    ),
    params(
        GetCredentialQuery
    ),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_credential_list(
    state: State<AppState>,
    Qs(query): Qs<GetCredentialQuery>,
) -> Response {
    let result = state
        .core
        .credential_service
        .get_credential_list(query.into())
        .await;

    match result {
        Ok(value) => (StatusCode::OK, Json(GetCredentialsResponseDTO::from(value))).into_response(),
        Err(error) => match error {
            ServiceError::NotFound => StatusCode::NOT_FOUND.into_response(),
            _ => {
                tracing::error!("Error while getting credential list: {:?}", error);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
    }
}

#[utoipa::path(
    post,
    path = "/api/credential/v1",
    request_body = CreateCredentialRequestRestDTO,
    responses(
        (status = 201, description = "Created", body = EntityResponseRestDTO),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Credential schema or DID not found"),
    ),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn post_credential(
    state: State<AppState>,
    Json(request): Json<CreateCredentialRequestRestDTO>,
) -> Response {
    let result = state
        .core
        .credential_service
        .create_credential(request.into())
        .await;

    match result {
        Ok(value) => (
            StatusCode::CREATED,
            Json(EntityResponseRestDTO { id: value }),
        )
            .into_response(),
        Err(error) => match error {
            ServiceError::NotFound => StatusCode::NOT_FOUND.into_response(),
            ServiceError::IncorrectParameters => StatusCode::BAD_REQUEST.into_response(),
            ServiceError::ConfigValidationError(error) => {
                tracing::error!("Config validation error: {:?}", error);
                (
                    StatusCode::BAD_REQUEST,
                    format!("Config validation error: {:?}", error),
                )
                    .into_response()
            }
            _ => {
                tracing::error!("Error while creating credential: {:?}", error);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
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
            ServiceError::NotFound => StatusCode::NOT_FOUND.into_response(),
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
            Json(vector_into::<
                CredentialRevocationCheckResponseRestDTO,
                CredentialRevocationCheckResponseDTO,
            >(values)),
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

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Extension, Json};

use uuid::Uuid;

use one_core::service::error::ServiceError;

use crate::dto::common::{EntityResponseRestDTO, GetCredentialsResponseDTO};
use crate::endpoint::credential::dto::{
    CreateCredentialRequestRestDTO, GetCredentialQuery, GetCredentialResponseRestDTO,
};
use crate::endpoint::credential::mapper::share_credentials_to_entity_share_response;
use crate::{AppState, Config};

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
    Query(query): Query<GetCredentialQuery>,
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
        (status = 200, description = "Created", body = EntityResponseRestDTO),
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
        Ok(value) => (StatusCode::OK, Json(EntityResponseRestDTO { id: value })).into_response(),
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
                tracing::error!("Error while getting credential: {:?}", error);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
    }
}

#[utoipa::path(
    post,
    path = "/api/credential/v1/{id}/share",
    responses(
        (status = 200, description = "Created", body = EntityShareResponseRestDTO),
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
pub(crate) async fn share_credential(
    Extension(config): Extension<Config>,
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> Response {
    let result = state.core.credential_service.share_credential(&id).await;

    match result {
        Ok(value) => (
            StatusCode::OK,
            Json(share_credentials_to_entity_share_response(
                value,
                &config.core_base_url,
            )),
        )
            .into_response(),
        Err(error) => match error {
            ServiceError::NotFound => StatusCode::NOT_FOUND.into_response(),
            ServiceError::AlreadyExists => StatusCode::BAD_REQUEST.into_response(),
            other => {
                tracing::error!("Error while getting credential: {other:?}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
    }
}

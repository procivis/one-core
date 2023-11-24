use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};
use one_core::service::did::DidDeactivationError;
use one_core::service::error::ServiceError;
use shared_types::DidId;

use super::dto::{
    CreateDidRequestRestDTO, DidPatchRequestRestDTO, DidResponseRestDTO, GetDidQuery,
};
use crate::dto::common::{EntityResponseRestDTO, GetDidsResponseRestDTO};
use crate::extractor::Qs;
use crate::router::AppState;

#[utoipa::path(
    get,
    path = "/api/did/v1/{id}",
    responses(
        (status = 200, description = "OK", body = DidResponseRestDTO),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "DID not found"),
        (status = 500, description = "Server error"),
    ),
    params(
        ("id" = Uuid, Path, description = "DID id")
    ),
    tag = "did_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_did(state: State<AppState>, Path(id): Path<DidId>) -> Response {
    let result = state.core.did_service.get_did(&id).await;

    match result {
        Err(error) => match error {
            ServiceError::NotFound => (StatusCode::NOT_FOUND).into_response(),
            _ => {
                tracing::error!("Error while getting did details: {:?}", error);
                (StatusCode::INTERNAL_SERVER_ERROR).into_response()
            }
        },
        Ok(value) => match DidResponseRestDTO::try_from(value) {
            Ok(value) => (StatusCode::OK, Json(value)).into_response(),
            Err(error) => {
                tracing::error!("Error while encoding base64: {:?}", error);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
    }
}

#[utoipa::path(
    get,
    path = "/api/did/v1",
    responses(
        (status = 200, description = "OK", body = GetDidsResponseRestDTO),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Server error"),
    ),
    params(
        GetDidQuery
    ),
    tag = "did_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_did_list(state: State<AppState>, Qs(query): Qs<GetDidQuery>) -> Response {
    let result = state.core.did_service.get_did_list(query.into()).await;

    match result {
        Err(error) => {
            tracing::error!("Error while getting dids: {:?}", error);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Ok(value) => (StatusCode::OK, Json(GetDidsResponseRestDTO::from(value))).into_response(),
    }
}

#[utoipa::path(
    post,
    path = "/api/did/v1",
    request_body = Option<CreateDidRequestRestDTO>,
    responses(
        (status = 201, description = "Created", body = EntityResponseRestDTO),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Organisation not found"),
        (status = 409, description = "Did already exists"),
        (status = 500, description = "Internal server error")
    ),
    tag = "did_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn post_did(
    state: State<AppState>,
    Json(request): Json<CreateDidRequestRestDTO>,
) -> Response {
    let result = state.core.did_service.create_did(request.into()).await;

    match result {
        Err(ServiceError::AlreadyExists) => {
            tracing::error!("Did already exists");
            StatusCode::CONFLICT.into_response()
        }
        Err(ServiceError::IncorrectParameters | ServiceError::NotFound) => {
            tracing::error!("Organisation or key not found");
            StatusCode::NOT_FOUND.into_response()
        }
        Err(ServiceError::ConfigValidationError(message)) => {
            tracing::error!("Config validation error: {}", message);
            StatusCode::BAD_REQUEST.into_response()
        }
        Err(ServiceError::ValidationError(message)) => {
            tracing::error!("Validation error: {}", message);
            StatusCode::BAD_REQUEST.into_response()
        }
        Err(e) => {
            tracing::error!("Error while creating did: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Ok(id) => (
            StatusCode::CREATED,
            Json(EntityResponseRestDTO { id: id.into() }),
        )
            .into_response(),
    }
}

#[utoipa::path(
    patch,
    path = "/api/did/v1/{id}",
    request_body = DidPatchRequestRestDTO,
    responses(
        (status = 204, description = "Created"),
        (status = 400, description = "Did cannot be deactivated"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Did not found"),
        (status = 409, description = "Did already deactivated"),
        (status = 500, description = "Internal server error")
    ),
    tag = "did_management",
    params(
        ("id" = DidId, Path, description = "DID id")
    ),
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn update_did(
    state: State<AppState>,
    Path(id): Path<DidId>,
    Json(request): Json<DidPatchRequestRestDTO>,
) -> Response {
    match state.core.did_service.update_did(&id, request.into()).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(ref error @ ServiceError::DidDeactivation(ref did_activation_err)) => {
            match did_activation_err {
                DidDeactivationError::DeactivatedSameValue { .. } => {
                    tracing::error!(%error, %id, "DID deactivation has already has been updated");
                    StatusCode::CONFLICT.into_response()
                }
                DidDeactivationError::CannotBeDeactivated { .. } => {
                    tracing::error!(%error, %id, "DID cannot be deactivated");
                    StatusCode::BAD_REQUEST.into_response()
                }
                DidDeactivationError::RemoteDid => {
                    tracing::error!(%id, "Remote DID cannot be deactivated");
                    StatusCode::BAD_REQUEST.into_response()
                }
            }
        }
        Err(ServiceError::NotFound) => {
            tracing::error!(%id, "DID not found");
            StatusCode::NOT_FOUND.into_response()
        }
        Err(error) => {
            tracing::error!(%error, %id, "Error while updating DID");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

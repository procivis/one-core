use std::sync::Arc;

use super::dto::{
    CreateProofRequestRestDTO, GetProofQuery, PresentationDefinitionResponseRestDTO,
    ProofDetailResponseRestDTO,
};
use crate::dto::common::{EntityResponseRestDTO, EntityShareResponseRestDTO};
use crate::dto::common::{GetProofsResponseRestDTO, OkOrErrorResponse};
use crate::extractor::Qs;
use crate::router::AppState;
use crate::ServerConfig;
use axum::Extension;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use one_core::service::error::{BusinessLogicError, ServiceError};
use uuid::Uuid;

#[utoipa::path(
    get,
    path = "/api/proof-request/v1/{id}/presentation-definition",
    responses(OkOrErrorResponse<PresentationDefinitionResponseRestDTO>),
    params(
        ("id" = Uuid, Path, description = "Proof id")
    ),
    tag = "proof_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_proof_presentation_definition(
    config: Extension<Arc<ServerConfig>>,
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> OkOrErrorResponse<PresentationDefinitionResponseRestDTO> {
    let result = state
        .core
        .proof_service
        .get_proof_presentation_definition(&id)
        .await;

    match result {
        Ok(value) => OkOrErrorResponse::ok(value),
        Err(error) => {
            tracing::error!(%error, "Error while getting presentation definition");
            OkOrErrorResponse::from_service_error(error, config.hide_error_response_cause)
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/proof-request/v1/{id}",
    responses(
        (status = 200, description = "OK", body = ProofDetailResponseRestDTO),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Credential not found"),
    ),
    params(
        ("id" = Uuid, Path, description = "Proof id")
    ),
    tag = "proof_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_proof_details(state: State<AppState>, Path(id): Path<Uuid>) -> Response {
    let result = state.core.proof_service.get_proof(&id).await;

    match result {
        Ok(value) => (
            StatusCode::OK,
            Json(ProofDetailResponseRestDTO::from(value)),
        )
            .into_response(),
        Err(error) => match error {
            ServiceError::NotFound => StatusCode::NOT_FOUND.into_response(),
            _ => {
                tracing::error!("Error while getting proof {error}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
    }
}

#[utoipa::path(
    get,
    path = "/api/proof-request/v1",
    responses(
        (status = 200, description = "OK", body = GetProofsResponseRestDTO),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Server error"),
    ),
    params(
        GetProofQuery
    ),
    tag = "proof_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_proofs(state: State<AppState>, Qs(query): Qs<GetProofQuery>) -> Response {
    let result = state.core.proof_service.get_proof_list(query.into()).await;

    match result {
        Err(error) => {
            tracing::error!("Error while getting proofs: {:?}", error);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Ok(value) => (StatusCode::OK, Json(GetProofsResponseRestDTO::from(value))).into_response(),
    }
}

#[utoipa::path(
    post,
    path = "/api/proof-request/v1",
    request_body = CreateProofRequestRestDTO,
    responses(
        (status = 201, description = "Created", body = EntityResponseRestDTO),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Proof schema or Verifier DID not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "proof_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn post_proof(
    state: State<AppState>,
    Json(request): Json<CreateProofRequestRestDTO>,
) -> Response {
    let result = state.core.proof_service.create_proof(request.into()).await;

    match result {
        Err(ServiceError::IncorrectParameters) => {
            tracing::error!("Invalid parameters: {:?}", result);
            StatusCode::BAD_REQUEST.into_response()
        }
        Err(ServiceError::NotFound) => {
            tracing::error!("Missing Proof schema or Verifier DID");
            StatusCode::NOT_FOUND.into_response()
        }
        Err(ServiceError::BusinessLogic(BusinessLogicError::DidIsDeactivated(_))) => {
            tracing::error!("DID has been deactivated");
            StatusCode::BAD_REQUEST.into_response()
        }
        Err(e) => {
            tracing::error!("Error while creating proof {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Ok(id) => (StatusCode::CREATED, Json(EntityResponseRestDTO { id })).into_response(),
    }
}

#[utoipa::path(
    post,
    path = "/api/proof-request/v1/{id}/share",
    responses(OkOrErrorResponse<EntityShareResponseRestDTO>),
    params(
        ("id" = Uuid, Path, description = "Proof id")
    ),
    tag = "proof_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn share_proof(
    config: Extension<Arc<ServerConfig>>,
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> OkOrErrorResponse<EntityShareResponseRestDTO> {
    let result = state.core.proof_service.share_proof(&id).await;

    match result {
        Ok(value) => OkOrErrorResponse::ok(value),
        Err(error) => {
            tracing::error!(%error, "Error while sharing proof");
            OkOrErrorResponse::from_service_error(error, config.hide_error_response_cause)
        }
    }
}

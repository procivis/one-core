use super::dto::{
    CreateProofRequestRestDTO, GetProofQuery, PresentationDefinitionResponseRestDTO,
    ProofDetailResponseRestDTO,
};
use crate::dto::common::GetProofsResponseRestDTO;
use crate::dto::common::{EntityResponseRestDTO, EntityShareResponseRestDTO};
use crate::extractor::Qs;
use crate::router::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use one_core::service::error::ServiceError;
use uuid::Uuid;

#[utoipa::path(
    get,
    path = "/api/proof-request/v1/{id}/presentation-definition",
    responses(
        (status = 200, description = "OK", body = PresentationDefinitionResponseRestDTO),
        (status = 400, description = "Referenced proof request is sent in verifier role (i.e. not as holder)"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Proof request not found"),
        (status = 409, description = "Proof not in pending state"),
    ),
    params(
        ("id" = Uuid, Path, description = "Proof id")
    ),
    tag = "proof_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_proof_presentation_definition(
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> Response {
    let result = state
        .core
        .proof_service
        .get_proof_presentation_definition(&id)
        .await;

    match result {
        Ok(value) => (
            StatusCode::OK,
            Json(PresentationDefinitionResponseRestDTO::from(value)),
        )
            .into_response(),
        Err(error) => match error {
            ServiceError::AlreadyExists => StatusCode::CONFLICT.into_response(),
            ServiceError::IncorrectParameters => StatusCode::BAD_REQUEST.into_response(),
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
        Err(ServiceError::DidDeactivated) => {
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
    responses(
        (status = 200, description = "OK", body = EntityShareResponseRestDTO),
        (status = 400, description = "Proof has been shared already"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "proof schema or DID not found"),
    ),
    params(
        ("id" = Uuid, Path, description = "Proof id")
    ),
    tag = "proof_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn share_proof(state: State<AppState>, Path(id): Path<Uuid>) -> Response {
    let result = state.core.proof_service.share_proof(&id).await;

    match result {
        Ok(value) => (
            StatusCode::OK,
            Json(EntityShareResponseRestDTO::from(value)),
        )
            .into_response(),
        Err(error) => match error {
            ServiceError::NotFound => StatusCode::NOT_FOUND.into_response(),
            ServiceError::AlreadyExists => StatusCode::BAD_REQUEST.into_response(),
            other => {
                tracing::error!("Error while sharing proof: {other:?}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
    }
}

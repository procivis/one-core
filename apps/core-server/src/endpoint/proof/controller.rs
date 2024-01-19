use super::dto::{
    CreateProofRequestRestDTO, GetProofQuery, PresentationDefinitionResponseRestDTO,
    ProofDetailResponseRestDTO,
};
use crate::dto::common::GetProofsResponseRestDTO;
use crate::dto::common::{EntityResponseRestDTO, EntityShareResponseRestDTO};
use crate::dto::response::{
    declare_utoipa_alias, AliasResponse, CreatedOrErrorResponse, OkOrErrorResponse,
};
use crate::extractor::Qs;

use crate::router::AppState;

use axum::{
    extract::{Path, State},
    Json,
};
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
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> OkOrErrorResponse<PresentationDefinitionResponseRestDTO> {
    let result = state
        .core
        .proof_service
        .get_proof_presentation_definition(&id)
        .await;
    OkOrErrorResponse::from_result(result, state, "getting presentation definition")
}

#[utoipa::path(
    get,
    path = "/api/proof-request/v1/{id}",
    responses(OkOrErrorResponse<ProofDetailResponseRestDTO>),
    params(
        ("id" = Uuid, Path, description = "Proof id")
    ),
    tag = "proof_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_proof_details(
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> OkOrErrorResponse<ProofDetailResponseRestDTO> {
    let result = state.core.proof_service.get_proof(&id).await;
    OkOrErrorResponse::from_result(result, state, "getting proof")
}

declare_utoipa_alias!(GetProofsResponseRestDTO);

#[utoipa::path(
    get,
    path = "/api/proof-request/v1",
    responses(OkOrErrorResponse<AliasResponse<GetProofsResponseRestDTO>>),
    params(GetProofQuery),
    tag = "proof_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_proofs(
    state: State<AppState>,
    Qs(query): Qs<GetProofQuery>,
) -> OkOrErrorResponse<GetProofsResponseRestDTO> {
    let result = state.core.proof_service.get_proof_list(query.into()).await;
    OkOrErrorResponse::from_result(result, state, "getting proofs")
}

#[utoipa::path(
    post,
    path = "/api/proof-request/v1",
    request_body = CreateProofRequestRestDTO,
    responses(CreatedOrErrorResponse<EntityResponseRestDTO>),
    tag = "proof_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn post_proof(
    state: State<AppState>,
    Json(request): Json<CreateProofRequestRestDTO>,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let result = state.core.proof_service.create_proof(request.into()).await;
    CreatedOrErrorResponse::from_result(result, state, "creating proof")
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
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> OkOrErrorResponse<EntityShareResponseRestDTO> {
    let result = state.core.proof_service.share_proof(&id).await;
    OkOrErrorResponse::from_result(result, state, "sharing proof")
}
